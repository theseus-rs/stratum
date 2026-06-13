//! The preprocessor driver: directive execution and macro expansion.
//!
//! This module ties the pieces together. It consumes the preprocessing tokens of a root
//! source file, executes directives (`#define`, `#undef`, `#include`, the conditional
//! family, `#line`, `#error`, `#pragma`), and performs macro expansion using a faithful
//! implementation of Prosser's algorithm with per-token hide sets (blue painting).

use crate::alloc_prelude::*;
use crate::eval::eval;
use crate::include::IncludeResolver;
use crate::macros::{MacroDef, is_va_args, parse_define};
use crate::util::{is_identifier, spelling, stringize};
use stratum_arena::{Interner, Symbol};
use stratum_c_lexer::{PpToken, PpTokenKind, Punctuator, lex};
use stratum_diagnostics::{Diagnostic, FileId, Label, Severity, SourceMap, Span};
use stratum_utils::{HashMap, HashSet};

/// The maximum `#include` nesting depth before bailing out.
const MAX_INCLUDE_DEPTH: usize = 200;

/// The result of preprocessing a translation unit.
#[derive(Debug, Default)]
pub struct PreprocessResult {
    /// The fully expanded preprocessing-token stream (newlines removed).
    pub tokens: Vec<PpToken>,
    /// Diagnostics produced during preprocessing.
    pub diagnostics: Vec<Diagnostic>,
}

impl PreprocessResult {
    /// Returns `true` if any error-severity diagnostics were produced.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity() == Severity::Error)
    }
}

/// A token paired with its hide set, the unit of Prosser's expansion algorithm.
#[derive(Clone)]
struct WToken {
    tok: PpToken,
    hide: HashSet<Symbol>,
}

/// State for one `#if`/`#ifdef`/`#ifndef` group.
struct Cond {
    /// Whether the currently selected branch is active (already folds in ancestor activity).
    taken: bool,
    /// Whether any branch in this group has been taken yet.
    done: bool,
    /// Whether `#else` has been seen.
    seen_else: bool,
}

/// Preprocesses `source` (the text of `file`).
///
/// `file` must already be registered in `source_map` (typically via
/// [`SourceMap::add_root`]). Includes are pulled in through `resolver` and registered in the
/// source map with full provenance.
#[must_use]
pub fn preprocess<R: IncludeResolver>(
    file: FileId,
    source: &str,
    interner: &mut Interner,
    source_map: &mut SourceMap,
    resolver: &mut R,
) -> PreprocessResult {
    let mut pp = Preprocessor {
        interner,
        source_map,
        resolver,
        macros: HashMap::default(),
        diagnostics: Vec::new(),
        output: Vec::new(),
        conds: Vec::new(),
        depth: 0,
    };
    pp.run(file, source);
    PreprocessResult {
        tokens: pp.output,
        diagnostics: pp.diagnostics,
    }
}

struct Preprocessor<'a, R: IncludeResolver> {
    interner: &'a mut Interner,
    source_map: &'a mut SourceMap,
    resolver: &'a mut R,
    macros: HashMap<Symbol, MacroDef>,
    diagnostics: Vec<Diagnostic>,
    output: Vec<PpToken>,
    conds: Vec<Cond>,
    depth: usize,
}

impl<R: IncludeResolver> Preprocessor<'_, R> {
    fn run(&mut self, file: FileId, source: &str) {
        lex(source, file, self.interner)
            .ok()
            .into_iter()
            .for_each(|lexed| {
                self.diagnostics.extend(lexed.diagnostics);
                self.process_lines(file, &lexed.tokens);
            });
    }

    fn active(&self) -> bool {
        self.conds.last().is_none_or(|c| c.taken)
    }

    fn process_lines(&mut self, file: FileId, tokens: &[PpToken]) {
        for line in split_lines(tokens) {
            let Some(first) = line.first() else { continue };
            if first.kind == PpTokenKind::Punct(Punctuator::Hash) && first.at_bol {
                self.directive(file, line.get(1..).unwrap_or_default(), first.span);
            } else if self.active() {
                self.expand_text_line(&line);
            }
        }
    }

    fn directive(&mut self, file: FileId, line: &[PpToken], hash: Span) {
        let Some(name_tok) = line.first() else {
            return; // null directive (`#` alone)
        };
        let PpTokenKind::Identifier(sym) = name_tok.kind else {
            if self.active() {
                self.error(hash, "invalid preprocessing directive");
            }
            return;
        };
        let name = self
            .interner
            .resolve(sym)
            .unwrap_or("<invalid>")
            .to_string();
        let rest = line.get(1..).unwrap_or_default();
        match name.as_str() {
            "if" => self.do_if(rest, hash),
            "ifdef" => self.do_ifdef(rest, hash, true),
            "ifndef" => self.do_ifdef(rest, hash, false),
            "elif" => self.do_elif(rest, hash),
            "else" => self.do_else(hash),
            "endif" => self.do_endif(hash),
            _ if !self.active() => {}
            "define" => self.do_define(rest, hash),
            "undef" => self.do_undef(rest, hash),
            "include" => self.do_include(file, rest, hash),
            "error" => self.do_error(rest, hash),
            "line" | "pragma" => {}
            _ => self.error(name_tok.span, "unknown preprocessing directive"),
        }
    }

    // --- Object/function macro definitions -------------------------------------------------

    fn do_define(&mut self, line: &[PpToken], hash: Span) {
        match parse_define(line, hash) {
            Ok(def) => {
                self.macros.insert(def.name, def);
            }
            Err(diag) => self.diagnostics.push(diag),
        }
    }

    fn do_undef(&mut self, line: &[PpToken], hash: Span) {
        match line.first().map(|t| t.kind) {
            Some(PpTokenKind::Identifier(sym)) => {
                self.macros.remove(&sym);
            }
            _ => self.error(hash, "`#undef` requires a macro name"),
        }
    }

    // --- Conditionals ----------------------------------------------------------------------

    fn do_if(&mut self, line: &[PpToken], hash: Span) {
        let taken = if self.active() {
            self.eval_condition(line, hash)
        } else {
            false
        };
        self.conds.push(Cond {
            taken,
            done: taken,
            seen_else: false,
        });
    }

    fn do_ifdef(&mut self, line: &[PpToken], hash: Span, want_defined: bool) {
        let defined = if let Some(PpTokenKind::Identifier(sym)) = line.first().map(|t| t.kind) {
            self.macros.contains_key(&sym)
        } else {
            self.error(hash, "expected a macro name");
            false
        };
        let taken = self.active() && (defined == want_defined);
        self.conds.push(Cond {
            taken,
            done: taken,
            seen_else: false,
        });
    }

    fn do_elif(&mut self, line: &[PpToken], hash: Span) {
        let Some(mut cond) = self.conds.pop() else {
            self.error(hash, "`#elif` without `#if`");
            return;
        };
        let parent_active = self.conds.iter().all(|c| c.taken);
        if cond.seen_else {
            self.conds.push(cond);
            self.error(hash, "`#elif` after `#else`");
            return;
        }
        if cond.done || !parent_active {
            cond.taken = false;
            self.conds.push(cond);
            return;
        }
        let taken = self.eval_condition(line, hash);
        cond.taken = taken;
        cond.done = taken;
        self.conds.push(cond);
    }

    fn do_else(&mut self, hash: Span) {
        let parent_active = self.parent_active();
        let Some(cond) = self.conds.last_mut() else {
            self.error(hash, "`#else` without `#if`");
            return;
        };
        if cond.seen_else {
            self.error(hash, "duplicate `#else`");
            return;
        }
        cond.seen_else = true;
        cond.taken = parent_active && !cond.done;
        cond.done = true;
    }

    fn do_endif(&mut self, hash: Span) {
        if self.conds.pop().is_none() {
            self.error(hash, "`#endif` without `#if`");
        }
    }

    fn parent_active(&self) -> bool {
        let len = self.conds.len();
        if len <= 1 {
            true
        } else {
            self.conds
                .get(..len - 1)
                .unwrap_or_default()
                .iter()
                .all(|c| c.taken)
        }
    }

    fn eval_condition(&mut self, line: &[PpToken], hash: Span) -> bool {
        let prepared = self.resolve_defined(line);
        let expanded = self.expand_to_pp(prepared);
        match eval(&expanded, self.interner, hash) {
            Ok(value) => value != 0,
            Err(diag) => {
                self.diagnostics.push(diag);
                false
            }
        }
    }

    /// Replaces `defined X` and `defined(X)` with `1` or `0` before macro expansion.
    fn resolve_defined(&mut self, line: &[PpToken]) -> Vec<PpToken> {
        let mut out = Vec::new();
        let mut i = 0;
        while let Some(&tok) = line.get(i) {
            if is_identifier(&tok, self.interner, "defined")
                && let Some((value, consumed)) =
                    self.match_defined(line.get(i + 1..).unwrap_or_default())
            {
                out.push(self.make_number(value, tok.span));
                i += 1 + consumed;
                continue;
            }
            out.push(tok);
            i += 1;
        }
        out
    }

    fn match_defined(&self, rest: &[PpToken]) -> Option<(i64, usize)> {
        match rest.first().map(|t| t.kind) {
            Some(PpTokenKind::Identifier(sym)) => {
                Some((i64::from(self.macros.contains_key(&sym)), 1))
            }
            Some(PpTokenKind::Punct(Punctuator::LParen)) => {
                let name = rest.get(1)?;
                let PpTokenKind::Identifier(sym) = name.kind else {
                    return None;
                };
                if rest.get(2)?.kind != PpTokenKind::Punct(Punctuator::RParen) {
                    return None;
                }
                Some((i64::from(self.macros.contains_key(&sym)), 3))
            }
            _ => None,
        }
    }

    // --- Includes --------------------------------------------------------------------------

    fn do_include(&mut self, file: FileId, line: &[PpToken], hash: Span) {
        let Some((name, angled)) = self.include_target(line, hash) else {
            return;
        };
        if self.depth >= MAX_INCLUDE_DEPTH {
            self.error(hash, "`#include` nested too deeply");
            return;
        }
        let current = self.source_map.file(file).map(|f| f.name().to_string());
        let Some(resolved) = self.resolver.resolve(&name, angled, current.as_deref()) else {
            self.error(hash, &format!("cannot find include `{name}`"));
            return;
        };
        self.source_map
            .add_include(resolved.name, resolved.contents.clone(), file, hash)
            .ok()
            .into_iter()
            .for_each(|included| {
                self.depth += 1;
                self.run(included, &resolved.contents);
                self.depth -= 1;
            });
    }

    /// Determines the include target spelling and whether it used angle brackets.
    fn include_target(&mut self, line: &[PpToken], hash: Span) -> Option<(String, bool)> {
        let expanded = self.expand_to_pp(line.to_vec());
        let Some(first) = expanded.first() else {
            self.error(hash, "`#include` expects \"file\" or <file>");
            return None;
        };
        match first.kind {
            PpTokenKind::StringLit(_) => {
                let raw = spelling(first, self.interner);
                Some((raw.trim_matches('"').to_string(), false))
            }
            PpTokenKind::Punct(Punctuator::Lt) => {
                let name =
                    self.reconstruct_angle_name(expanded.get(1..).unwrap_or_default(), hash)?;
                Some((name, true))
            }
            _ => {
                self.error(hash, "`#include` expects \"file\" or <file>");
                None
            }
        }
    }

    fn reconstruct_angle_name(&mut self, tokens: &[PpToken], hash: Span) -> Option<String> {
        let mut name = String::new();
        for tok in tokens {
            if tok.kind == PpTokenKind::Punct(Punctuator::Gt) {
                return Some(name);
            }
            if tok.leading_whitespace && !name.is_empty() {
                name.push(' ');
            }
            name.push_str(&spelling(tok, self.interner));
        }
        self.error(hash, "missing closing `>` in `#include`");
        None
    }

    fn do_error(&mut self, line: &[PpToken], hash: Span) {
        let text: Vec<String> = line.iter().map(|t| spelling(t, self.interner)).collect();
        self.error(hash, &format!("#error {}", text.join(" ")));
    }

    // --- Macro expansion (Prosser's algorithm) ---------------------------------------------

    fn expand_text_line(&mut self, line: &[PpToken]) {
        let input = line.iter().map(|&tok| WToken::bare(tok)).collect();
        let expanded = self.expand(input);
        self.output.extend(expanded.into_iter().map(|w| w.tok));
    }

    fn expand_to_pp(&mut self, line: Vec<PpToken>) -> Vec<PpToken> {
        let input = line.into_iter().map(WToken::bare).collect();
        self.expand(input).into_iter().map(|w| w.tok).collect()
    }

    fn expand(&mut self, input: Vec<WToken>) -> Vec<WToken> {
        let mut input: VecDeque<WToken> = input.into();
        let mut output = Vec::new();
        while let Some(item) = input.pop_front() {
            let PpTokenKind::Identifier(name) = item.tok.kind else {
                output.push(item);
                continue;
            };
            if item.hide.contains(&name) {
                output.push(item);
                continue;
            }
            let Some(def) = self.macros.get(&name).cloned() else {
                output.push(item);
                continue;
            };
            if def.is_function_like() {
                if !self.invoke_function_macro(&item, &def, &mut input) {
                    output.push(item);
                }
            } else {
                self.invoke_object_macro(&item, &def, &mut input);
            }
        }
        output
    }

    fn invoke_object_macro(&mut self, item: &WToken, def: &MacroDef, input: &mut VecDeque<WToken>) {
        let mut hide = item.hide.clone();
        hide.insert(def.name);
        let repl = self.subst(def, &[], &hide, item.tok.span);
        prepend(input, repl);
    }

    /// Returns `false` if the macro name is not actually followed by `(` (treat as plain id).
    fn invoke_function_macro(
        &mut self,
        item: &WToken,
        def: &MacroDef,
        input: &mut VecDeque<WToken>,
    ) -> bool {
        if !matches!(
            input.front().map(|w| w.tok.kind),
            Some(PpTokenKind::Punct(Punctuator::LParen))
        ) {
            return false;
        }
        let Some((args, close)) = collect_args(input) else {
            self.error(item.tok.span, "unterminated macro argument list");
            return true;
        };
        let arity = def.params.as_ref().map_or(0, Vec::len);
        if !self.check_arity(def, &args, item.tok.span) {
            return true;
        }
        let mut hide: HashSet<Symbol> = item.hide.intersection(&close.hide).copied().collect();
        hide.insert(def.name);
        let normalized = normalize_args(args, arity, def.variadic);
        let repl = self.subst(def, &normalized, &hide, item.tok.span);
        prepend(input, repl);
        true
    }

    fn check_arity(&mut self, def: &MacroDef, args: &[Vec<WToken>], span: Span) -> bool {
        let arity = def.params.as_ref().map_or(0, Vec::len);
        let supplied = if matches!(args, [arg] if arg.is_empty()) {
            0
        } else {
            args.len()
        };
        if def.variadic && supplied >= arity {
            return true;
        }
        if !def.variadic && supplied == arity {
            return true;
        }
        self.error(span, "macro invoked with the wrong number of arguments");
        false
    }

    /// Substitutes parameters in a macro body, applying `#`, `##`, and the hide set.
    fn subst(
        &mut self,
        def: &MacroDef,
        args: &[Vec<WToken>],
        hide: &HashSet<Symbol>,
        call_site: Span,
    ) -> Vec<WToken> {
        let mut os: Vec<WToken> = Vec::new();
        let mut pending_paste = false;
        let mut j = 0;
        while let Some(&tok) = def.body.get(j) {
            let next_paste = matches!(
                def.body.get(j + 1).map(|t| t.kind),
                Some(PpTokenKind::Punct(Punctuator::HashHash))
            );

            if tok.kind == PpTokenKind::Punct(Punctuator::Hash)
                && def.is_function_like()
                && let Some(arg) = self.body_param_arg(def, args, def.body.get(j + 1))
            {
                let text = stringize_w(&arg, self.interner);
                os.push(self.make_string_w(&text, tok.span));
                j += 2;
                continue;
            }

            if tok.kind == PpTokenKind::Punct(Punctuator::HashHash) {
                pending_paste = true;
                j += 1;
                continue;
            }

            let produced = self.subst_token(def, args, tok, next_paste || pending_paste, call_site);
            self.emit(&mut os, produced, &mut pending_paste, tok.span);
            j += 1;
        }
        hsadd(&mut os, hide);
        os
    }

    fn emit(
        &mut self,
        os: &mut Vec<WToken>,
        produced: Vec<WToken>,
        pending_paste: &mut bool,
        span: Span,
    ) {
        if *pending_paste {
            *pending_paste = false;
            self.paste(os, produced, span);
        } else {
            os.extend(produced);
        }
    }

    /// Resolves a single body token to its substitution (a parameter's argument or itself).
    fn subst_token(
        &mut self,
        def: &MacroDef,
        args: &[Vec<WToken>],
        tok: PpToken,
        raw: bool,
        call_site: Span,
    ) -> Vec<WToken> {
        if let Some(index) = self.param_index(def, &tok) {
            let arg = args.get(index).cloned().unwrap_or_default();
            return if raw { arg } else { self.expand(arg) };
        }
        vec![WToken::bare(PpToken {
            span: call_site,
            ..tok
        })]
    }

    fn body_param_arg(
        &self,
        def: &MacroDef,
        args: &[Vec<WToken>],
        next: Option<&PpToken>,
    ) -> Option<Vec<WToken>> {
        let next = next?;
        let index = self.param_index(def, next)?;
        Some(args.get(index).cloned().unwrap_or_default())
    }

    fn param_index(&self, def: &MacroDef, tok: &PpToken) -> Option<usize> {
        let params = def.params.as_deref()?;
        if let PpTokenKind::Identifier(sym) = tok.kind
            && let Some(pos) = params.iter().position(|p| *p == sym)
        {
            return Some(pos);
        }
        if def.variadic && is_va_args(tok, self.interner) {
            return Some(params.len());
        }
        None
    }

    /// Pastes the trailing token of `os` with the first token of `rhs` (the `##` operator).
    fn paste(&mut self, os: &mut Vec<WToken>, mut rhs: Vec<WToken>, span: Span) {
        let mut iter = rhs.drain(..);
        let Some(right) = iter.next() else {
            return; // placemarker: nothing to paste
        };
        let remainder: Vec<WToken> = iter.collect();
        let Some(left) = os.pop() else {
            os.push(right);
            os.extend(remainder);
            return;
        };
        let text = format!(
            "{}{}",
            spelling(&left.tok, self.interner),
            spelling(&right.tok, self.interner)
        );
        let pasted = self.relex(&text, span);
        if pasted.is_empty() {
            self.error(span, "`##` produced an invalid token");
            os.push(left);
        } else {
            os.extend(pasted);
        }
        os.extend(remainder);
    }

    fn relex(&mut self, text: &str, span: Span) -> Vec<WToken> {
        let lexed = lex(text, span.file(), self.interner).unwrap_or_default();
        lexed
            .tokens
            .into_iter()
            .filter(|t| t.kind != PpTokenKind::Newline)
            .map(|t| WToken::bare(PpToken { span, ..t }))
            .collect()
    }

    // --- Token synthesis & diagnostics -----------------------------------------------------

    fn make_number(&mut self, value: i64, span: Span) -> PpToken {
        let text = value.to_string();
        let result = self.interner.intern(&text);
        let sym = self.synthesized_symbol(result, span, "number");
        PpToken {
            kind: PpTokenKind::Number(sym),
            span,
            leading_whitespace: true,
            at_bol: false,
        }
    }

    fn make_string_w(&mut self, text: &str, span: Span) -> WToken {
        let result = self.interner.intern(text);
        let sym = self.synthesized_symbol(result, span, "string");
        WToken::bare(PpToken {
            kind: PpTokenKind::StringLit(sym),
            span,
            leading_whitespace: true,
            at_bol: false,
        })
    }

    fn synthesized_symbol(
        &mut self,
        result: stratum_arena::Result<Symbol>,
        span: Span,
        what: &str,
    ) -> Symbol {
        match result {
            Ok(sym) => sym,
            Err(err) => {
                let message = format!("failed to intern preprocessor {what}: {err}");
                self.error(span, &message);
                Symbol::default()
            }
        }
    }

    fn error(&mut self, span: Span, message: &str) {
        self.diagnostics
            .push(Diagnostic::error(message.to_string()).with_label(Label::new(span, "here")));
    }
}

impl WToken {
    fn bare(tok: PpToken) -> Self {
        Self {
            tok,
            hide: HashSet::default(),
        }
    }
}

/// Splits a token stream into logical lines, dropping the newline markers.
fn split_lines(tokens: &[PpToken]) -> Vec<Vec<PpToken>> {
    let mut lines = Vec::new();
    let mut current = Vec::new();
    for &tok in tokens {
        if tok.kind == PpTokenKind::Newline {
            lines.push(core::mem::take(&mut current));
        } else {
            current.push(tok);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// Pushes `tokens` to the front of `input` preserving their order (for rescanning).
fn prepend(input: &mut VecDeque<WToken>, tokens: Vec<WToken>) {
    for tok in tokens.into_iter().rev() {
        input.push_front(tok);
    }
}

/// Collects a function-like macro's arguments, consuming through the closing `)`.
///
/// Assumes the next token in `input` is the opening `(`. Returns the per-argument token
/// lists and the closing-paren token (for hide-set intersection), or `None` if unterminated.
fn collect_args(input: &mut VecDeque<WToken>) -> Option<(Vec<Vec<WToken>>, WToken)> {
    input.pop_front()?; // consume `(`
    let mut args: Vec<Vec<WToken>> = vec![Vec::new()];
    let mut depth = 0usize;
    loop {
        let item = input.pop_front()?;
        match item.tok.kind {
            PpTokenKind::Punct(Punctuator::LParen) => {
                depth += 1;
                push_arg_token(&mut args, item);
            }
            PpTokenKind::Punct(Punctuator::RParen) if depth == 0 => {
                return Some((args, item));
            }
            PpTokenKind::Punct(Punctuator::RParen) => {
                depth -= 1;
                push_arg_token(&mut args, item);
            }
            PpTokenKind::Punct(Punctuator::Comma) if depth == 0 => {
                args.push(Vec::new());
            }
            _ => push_arg_token(&mut args, item),
        }
    }
}

fn push_arg_token(args: &mut [Vec<WToken>], item: WToken) {
    if let Some(arg) = args.last_mut() {
        arg.push(item);
    }
}

/// Merges trailing arguments into a single `__VA_ARGS__` argument for variadic macros.
fn normalize_args(mut args: Vec<Vec<WToken>>, arity: usize, variadic: bool) -> Vec<Vec<WToken>> {
    if matches!(args.as_slice(), [arg] if arg.is_empty()) && arity == 0 {
        return Vec::new();
    }
    if !variadic {
        return args;
    }
    if args.len() <= arity {
        args.push(Vec::new());
        return args;
    }
    let mut merged: Vec<WToken> = Vec::new();
    for (i, arg) in args.split_off(arity).into_iter().enumerate() {
        if i > 0
            && let Some(first) = arg.first()
        {
            merged.push(WToken::bare(PpToken {
                kind: PpTokenKind::Punct(Punctuator::Comma),
                span: first.tok.span,
                leading_whitespace: false,
                at_bol: false,
            }));
        }
        merged.extend(arg);
    }
    args.push(merged);
    args
}

/// Adds `hide` to the hide set of every token in `tokens`.
fn hsadd(tokens: &mut [WToken], hide: &HashSet<Symbol>) {
    for tok in tokens {
        tok.hide.extend(hide.iter().copied());
    }
}

/// Stringizes a sequence of [`WToken`]s.
fn stringize_w(tokens: &[WToken], interner: &Interner) -> String {
    let raw: Vec<PpToken> = tokens.iter().map(|w| w.tok).collect();
    stringize(&raw, interner)
}

#[cfg(test)]
mod tests {
    use super::{
        Cond, MAX_INCLUDE_DEPTH, Preprocessor, WToken, collect_args, normalize_args,
        push_arg_token, split_lines,
    };
    use crate::alloc_prelude::*;
    use crate::include::MapIncludeResolver;
    use crate::preprocessor::{PreprocessResult, preprocess};
    use crate::util::spelling;
    use stratum_arena::{Interner, Symbol};
    use stratum_c_lexer::{PpToken, PpTokenKind, Punctuator, lex};
    use stratum_diagnostics::{Diagnostic, FileId, SourceMap, Span};

    fn lex_tokens(src: &str, interner: &mut Interner) -> Vec<PpToken> {
        lex(src, FileId::from_raw(0), interner)
            .unwrap()
            .tokens
            .into_iter()
            .filter(|tok| !matches!(tok.kind, PpTokenKind::Newline))
            .collect()
    }

    fn with_preprocessor<'a>(
        interner: &'a mut Interner,
        map: &'a mut SourceMap,
        resolver: &'a mut MapIncludeResolver,
    ) -> Preprocessor<'a, MapIncludeResolver> {
        Preprocessor {
            interner,
            source_map: map,
            resolver,
            macros: stratum_utils::HashMap::default(),
            diagnostics: Vec::new(),
            output: Vec::new(),
            conds: Vec::new(),
            depth: 0,
        }
    }

    #[test]
    fn preprocess_result_reports_error_diagnostics() {
        let result = PreprocessResult {
            tokens: Vec::new(),
            diagnostics: vec![Diagnostic::error("bad")],
        };
        assert!(result.has_errors());

        let result = PreprocessResult {
            tokens: Vec::new(),
            diagnostics: Vec::new(),
        };
        assert!(!result.has_errors());
    }

    #[test]
    fn split_lines_keeps_final_line_without_newline() {
        let span = Span::point(FileId::from_raw(0), 0);
        let token = PpToken {
            kind: PpTokenKind::Other('x'),
            span,
            leading_whitespace: false,
            at_bol: true,
        };

        let lines = split_lines(&[token]);

        assert_eq!(lines.len(), 1);
        assert_eq!(lines.first(), Some(&vec![token]));
    }

    #[test]
    fn synthesized_symbol_errors_are_reported() {
        let mut map = SourceMap::new();
        let mut interner = Interner::new();
        let mut resolver = MapIncludeResolver::new();
        let mut pp = with_preprocessor(&mut interner, &mut map, &mut resolver);
        let span = Span::point(FileId::from_raw(0), 0);

        assert_eq!(
            pp.synthesized_symbol(Err(stratum_arena::Error::InternerFull), span, "number"),
            Symbol::default()
        );
        assert_eq!(pp.diagnostics.len(), 1);
    }

    #[test]
    fn private_directive_and_condition_edges_are_covered_directly() {
        fn token(kind: PpTokenKind, span: Span) -> PpToken {
            PpToken {
                kind,
                span,
                leading_whitespace: false,
                at_bol: true,
            }
        }

        let mut map = SourceMap::new();
        let file = map.add_root("main.c", "").unwrap();
        let mut interner = Interner::new();
        let unknown = interner.intern("unknown").unwrap();
        let defined_name = interner.intern("DEFINED").unwrap();
        let mut resolver = MapIncludeResolver::new();
        let mut pp = with_preprocessor(&mut interner, &mut map, &mut resolver);
        let span = Span::point(file, 0);

        pp.directive(file, &[], span);
        pp.directive(file, &[token(PpTokenKind::Identifier(unknown), span)], span);
        pp.do_define(&[token(PpTokenKind::Number(Symbol::default()), span)], span);
        pp.do_ifdef(&[], span, true);
        pp.do_endif(span);
        assert!(!pp.diagnostics.is_empty());

        let ident = token(PpTokenKind::Identifier(defined_name), span);
        assert_eq!(pp.match_defined(&[ident]), Some((0, 1)));
        assert_eq!(
            pp.match_defined(&[token(PpTokenKind::Punct(Punctuator::Plus), span)]),
            None
        );

        pp.conds.clear();
        pp.conds.push(Cond {
            taken: false,
            done: false,
            seen_else: false,
        });
        pp.do_if(&[], span);
        assert!(!pp.conds.last().is_some_and(|cond| cond.taken));

        pp.conds.clear();
        pp.conds.push(Cond {
            taken: true,
            done: true,
            seen_else: false,
        });
        pp.do_elif(&[], span);
        assert!(!pp.conds.last().is_some_and(|cond| cond.taken));

        pp.conds.clear();
        pp.conds.push(Cond {
            taken: true,
            done: false,
            seen_else: false,
        });
        pp.conds.push(Cond {
            taken: true,
            done: false,
            seen_else: false,
        });
        assert!(pp.parent_active());
    }

    #[test]
    fn directive_edge_errors_are_reported() {
        let mut map = SourceMap::new();
        let file = map.add_root("main.c", "").unwrap();
        let mut interner = Interner::new();
        let mut resolver = MapIncludeResolver::new();

        for src in [
            "# 123\n",
            "#undef\n",
            "#elif 1\n",
            "#else\n",
            "#if 0\n#else\n#elif 1\n#endif\n",
            "#if 0\n#else\n#else\n#endif\n",
            "#if defined(123)\n#endif\n",
            "#if defined(FOO + 1)\n#endif\n",
            "#include 123\n",
            "#include <missing\n",
        ] {
            let result = preprocess(file, src, &mut interner, &mut map, &mut resolver);
            assert!(result.has_errors(), "expected error for {src:?}");
        }
    }

    #[test]
    fn empty_and_inactive_directive_lines_are_ignored() {
        let mut map = SourceMap::new();
        let file = map.add_root("main.c", "").unwrap();
        let mut interner = Interner::new();
        let mut resolver = MapIncludeResolver::new();

        let result = preprocess(
            file,
            "\n#if 0\n# 123\n#unknown\n#endif\n",
            &mut interner,
            &mut map,
            &mut resolver,
        );

        assert!(!result.has_errors());
    }

    #[test]
    fn inactive_parent_skips_nested_if_condition() {
        let mut map = SourceMap::new();
        let file = map.add_root("main.c", "").unwrap();
        let mut interner = Interner::new();
        let mut resolver = MapIncludeResolver::new();

        let result = preprocess(
            file,
            "#if 0\n#if BAD +\n#error skipped\n#endif\n#endif\n",
            &mut interner,
            &mut map,
            &mut resolver,
        );
        assert!(!result.has_errors());
    }

    #[test]
    fn malformed_defined_operands_do_not_match_helper() {
        let mut map = SourceMap::new();
        let mut interner = Interner::new();
        let mut resolver = MapIncludeResolver::new();
        let pp = with_preprocessor(&mut interner, &mut map, &mut resolver);
        let malformed_parenthesized = lex_tokens("(FOO + 1)", pp.interner);
        let missing_name = lex_tokens("(", pp.interner);
        let missing_close = lex_tokens("(FOO", pp.interner);
        let leading_punctuator = lex_tokens("+ 1", pp.interner);

        assert_eq!(pp.match_defined(&malformed_parenthesized), None);
        assert_eq!(pp.match_defined(&missing_name), None);
        assert_eq!(pp.match_defined(&missing_close), None);
        assert_eq!(pp.match_defined(&leading_punctuator), None);
    }

    #[test]
    fn missing_include_target_reports_error() {
        let mut map = SourceMap::new();
        let file = map.add_root("main.c", "").unwrap();
        let mut interner = Interner::new();
        let mut resolver = MapIncludeResolver::new();

        let result = preprocess(file, "#include\n", &mut interner, &mut map, &mut resolver);

        assert!(result.has_errors());
    }

    #[test]
    fn angle_include_reconstructs_spaced_names() {
        let mut map = SourceMap::new();
        let file = map.add_root("main.c", "").unwrap();
        let mut interner = Interner::new();
        let mut resolver = MapIncludeResolver::new().with_file("sys header.h", "int y;\n");

        let result = preprocess(
            file,
            "#include <sys header.h>\n",
            &mut interner,
            &mut map,
            &mut resolver,
        );
        assert!(!result.has_errors());
        assert!(result.tokens.iter().any(|tok| {
            matches!(tok.kind, PpTokenKind::Identifier(sym) if interner.resolve(sym).unwrap_or("") == "y")
        }));
    }

    #[test]
    fn unterminated_function_macro_call_reports_error() {
        let mut map = SourceMap::new();
        let file = map.add_root("main.c", "").unwrap();
        let mut interner = Interner::new();
        let mut resolver = MapIncludeResolver::new();

        let result = preprocess(
            file,
            "#define F(x) x\nF(1\n",
            &mut interner,
            &mut map,
            &mut resolver,
        );
        assert!(result.has_errors());
    }

    #[test]
    fn zero_argument_function_macro_invokes_successfully() {
        let mut map = SourceMap::new();
        let file = map.add_root("main.c", "").unwrap();
        let mut interner = Interner::new();
        let mut resolver = MapIncludeResolver::new();

        let result = preprocess(
            file,
            "#define F() x\nF()\n",
            &mut interner,
            &mut map,
            &mut resolver,
        );

        assert!(!result.has_errors());
        assert!(result.tokens.iter().any(|tok| {
            matches!(tok.kind, PpTokenKind::Identifier(sym) if interner.resolve(sym).unwrap_or("") == "x")
        }));
    }

    #[test]
    fn successful_conditionals_defined_and_include_paths_expand() {
        let mut map = SourceMap::new();
        let file = map.add_root("main.c", "").unwrap();
        let mut interner = Interner::new();
        let mut resolver = MapIncludeResolver::new().with_file("hdr.h", "int from_header;\n");

        let result = preprocess(
            file,
            "#define FOO 1\n\
             #if 0\n\
             skipped\n\
             #elif defined(FOO)\n\
             selected\n\
             #else\n\
             skipped_else\n\
             #endif\n\
             #ifndef MISSING\n\
             missing_branch\n\
             #endif\n\
             #include \"hdr.h\"\n\
             #line 99\n\
             #pragma once\n",
            &mut interner,
            &mut map,
            &mut resolver,
        );

        assert!(!result.has_errors());
        let words: Vec<_> = result
            .tokens
            .iter()
            .map(|tok| spelling(tok, &interner))
            .collect();
        assert!(words.contains(&"selected".to_string()), "got: {words:?}");
        assert!(
            words.contains(&"missing_branch".to_string()),
            "got: {words:?}"
        );
        assert!(words.contains(&"from_header".to_string()), "got: {words:?}");
    }

    #[test]
    fn nested_include_runs_and_unwinds_depth() {
        let mut map = SourceMap::new();
        let file = map.add_root("main.c", "").unwrap();
        let mut interner = Interner::new();
        let mut resolver = MapIncludeResolver::new()
            .with_file("outer.h", "#include \"inner.h\"\n")
            .with_file("inner.h", "int nested;\n");

        let result = preprocess(
            file,
            "#include \"outer.h\"\n",
            &mut interner,
            &mut map,
            &mut resolver,
        );

        assert!(!result.has_errors());
        assert!(result.tokens.iter().any(|tok| {
            matches!(tok.kind, PpTokenKind::Identifier(sym) if interner.resolve(sym).unwrap_or("") == "nested")
        }));
    }

    #[test]
    fn macro_stringize_paste_plain_name_and_arity_paths_expand() {
        let mut map = SourceMap::new();
        let file = map.add_root("main.c", "").unwrap();
        let mut interner = Interner::new();
        let mut resolver = MapIncludeResolver::new();

        let result = preprocess(
            file,
            "#define OBJ value\n\
             #define CAT(a, b) a ## b\n\
             #define STR(x) #x\n\
             #define F(x) x\n\
             OBJ\n\
             CAT(to, ken)\n\
             STR(a b)\n\
             F\n\
             F(1, 2)\n",
            &mut interner,
            &mut map,
            &mut resolver,
        );

        assert!(result.has_errors());
        let words: Vec<_> = result
            .tokens
            .iter()
            .map(|tok| spelling(tok, &interner))
            .collect();
        assert!(words.contains(&"value".to_string()), "got: {words:?}");
        assert!(words.contains(&"token".to_string()), "got: {words:?}");
        assert!(words.contains(&"\"a b\"".to_string()), "got: {words:?}");
        assert!(words.contains(&"F".to_string()), "got: {words:?}");
    }

    #[test]
    fn direct_stringize_substitution_pushes_created_token() {
        let mut map = SourceMap::new();
        let mut interner = Interner::new();
        let mut resolver = MapIncludeResolver::new();
        let mut pp = with_preprocessor(&mut interner, &mut map, &mut resolver);
        let span = Span::point(FileId::from_raw(0), 0);
        let name = pp.interner.intern("x").unwrap();
        let def = crate::macros::MacroDef {
            name: pp.interner.intern("STR").unwrap(),
            params: Some(vec![name]),
            variadic: false,
            body: lex_tokens("#x", pp.interner),
            span,
        };
        let args = vec![
            lex_tokens("a b", pp.interner)
                .into_iter()
                .map(WToken::bare)
                .collect(),
        ];

        let out = pp.subst(&def, &args, &stratum_utils::HashSet::default(), span);

        assert_eq!(out.len(), 1);
        let strings = out
            .iter()
            .filter(|tok| matches!(tok.tok.kind, PpTokenKind::StringLit(_)))
            .count();
        assert_eq!(strings, 1);
    }

    #[test]
    fn include_depth_limit_is_enforced_before_resolution() {
        let mut map = SourceMap::new();
        let file = map.add_root("main.c", "#include \"hdr.h\"\n").unwrap();
        let mut interner = Interner::new();
        let mut resolver = MapIncludeResolver::new();
        let mut pp = with_preprocessor(&mut interner, &mut map, &mut resolver);
        pp.depth = MAX_INCLUDE_DEPTH;

        let line = lex_tokens("\"hdr.h\"", pp.interner);
        pp.do_include(file, &line, Span::point(file, 0));

        assert!(
            pp.diagnostics
                .iter()
                .any(|d| d.message().contains("deeply"))
        );
    }

    #[test]
    fn paste_handles_placemarkers_and_empty_left_side() {
        let mut map = SourceMap::new();
        let file = map.add_root("main.c", "").unwrap();
        let mut interner = Interner::new();
        let mut resolver = MapIncludeResolver::new();
        let mut pp = with_preprocessor(&mut interner, &mut map, &mut resolver);
        let span = Span::point(file, 0);

        let mut os = Vec::new();
        pp.paste(&mut os, Vec::new(), span);
        assert!(os.is_empty());

        let rhs: Vec<_> = lex_tokens("x y", pp.interner)
            .into_iter()
            .map(WToken::bare)
            .collect();
        pp.paste(&mut os, rhs, span);
        assert_eq!(os.len(), 2);

        let newline = WToken::bare(PpToken {
            kind: PpTokenKind::Newline,
            span,
            leading_whitespace: false,
            at_bol: false,
        });
        let mut os = vec![newline.clone()];
        pp.paste(&mut os, vec![newline], span);
        assert!(!pp.diagnostics.is_empty());
    }

    #[test]
    fn collect_args_handles_empty_missing_nested_and_plain_tokens() {
        let mut empty = VecDeque::new();
        assert!(collect_args(&mut empty).is_none());

        let mut interner = Interner::new();
        let mut missing_close: VecDeque<_> = lex_tokens("(a", &mut interner)
            .into_iter()
            .map(WToken::bare)
            .collect();
        assert!(collect_args(&mut missing_close).is_none());

        let mut nested: VecDeque<_> = lex_tokens("(a, (b, c))", &mut interner)
            .into_iter()
            .map(WToken::bare)
            .collect();
        let (args, _) = collect_args(&mut nested).unwrap();
        assert_eq!(args.len(), 2);
        assert_eq!(args.get(1).map(Vec::len), Some(5));

        let token = WToken::bare(PpToken {
            kind: PpTokenKind::Other('x'),
            span: Span::point(FileId::from_raw(0), 0),
            leading_whitespace: false,
            at_bol: false,
        });
        push_arg_token(&mut [], token);
    }

    #[test]
    fn variadic_normalization_adds_empty_va_args() {
        let mut interner = Interner::new();
        let args: Vec<Vec<WToken>> = vec![
            lex_tokens("a", &mut interner)
                .into_iter()
                .map(WToken::bare)
                .collect(),
        ];
        let normalized = normalize_args(args, 1, true);
        assert_eq!(normalized.len(), 2);
        assert!(normalized.get(1).is_some_and(Vec::is_empty));
    }
}
