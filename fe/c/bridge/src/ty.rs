//! Type lowering: C declaration specifiers and declarators into [`HirType`]s.

use crate::alloc_prelude::*;
use crate::lower::CLowering;
use stratum_c_ast::{DeclSpecifiers, Derivation, TypeQualifier, TypeSpecifier};
use stratum_hir::{HirContext, HirType, HirTypeId, IntWidth, Qualifiers, TagKind};

impl CLowering<'_> {
    /// Lowers a base specifier set plus a derivation chain into a HIR type id.
    ///
    /// Derivations are stored innermost-first, so they are folded in reverse to wrap the base
    /// type from the inside out (e.g. `int *a[3]` becomes `Array(Pointer(Int))`).
    pub(crate) fn lower_type(
        &mut self,
        cx: &mut HirContext,
        specifiers: &DeclSpecifiers,
        derivations: &[Derivation],
    ) -> crate::error::Result<HirTypeId> {
        let base = self.lower_base_type(cx, specifiers)?;
        let mut current = base;
        for derivation in derivations.iter().rev() {
            current = self.apply_derivation(cx, current, derivation)?;
        }
        Ok(current)
    }

    fn apply_derivation(
        &mut self,
        cx: &mut HirContext,
        inner: HirTypeId,
        derivation: &Derivation,
    ) -> crate::error::Result<HirTypeId> {
        match derivation {
            Derivation::Pointer { qualifiers } => {
                let pointer = cx.alloc_type(HirType::Pointer(inner))?;
                Self::wrap_qualifiers(cx, pointer, qualifiers_from(qualifiers))
            }
            Derivation::Array { size } => {
                let length = match size {
                    Some(s) => self.const_array_len(*s)?,
                    None => None,
                };
                cx.alloc_type(HirType::Array {
                    element: inner,
                    length,
                })
                .map_err(crate::error::Error::from)
            }
            Derivation::Function { params, variadic } => {
                let params = params.clone();
                let mut param_types = Vec::with_capacity(params.len());
                for param in &params {
                    let param_ty =
                        self.lower_type(cx, &param.specifiers, &param.declarator.derivations)?;
                    param_types.push(param_ty);
                }
                cx.alloc_type(HirType::Function {
                    params: param_types,
                    ret: inner,
                    variadic: *variadic,
                })
                .map_err(crate::error::Error::from)
            }
        }
    }

    fn lower_base_type(
        &mut self,
        cx: &mut HirContext,
        specifiers: &DeclSpecifiers,
    ) -> crate::error::Result<HirTypeId> {
        let ty = self.base_hir_type(cx, specifiers)?;
        let id = cx.alloc_type(ty)?;
        Self::wrap_qualifiers(cx, id, qualifiers_from(&specifiers.qualifiers))
    }

    fn base_hir_type(
        &mut self,
        cx: &mut HirContext,
        specifiers: &DeclSpecifiers,
    ) -> crate::error::Result<HirType> {
        let specs = &specifiers.type_specifiers;
        if let Some(tagged) = self.tagged_type(cx, specs)? {
            return Ok(tagged);
        }
        let unsigned = specs.contains(&TypeSpecifier::Unsigned);
        let signed = !unsigned;
        if specs.contains(&TypeSpecifier::Void) {
            return Ok(HirType::Void);
        }
        if specs.contains(&TypeSpecifier::Bool) {
            return Ok(HirType::Bool);
        }
        if specs.contains(&TypeSpecifier::Decimal128) {
            return Ok(HirType::Float { bits: 128 });
        }
        if specs.contains(&TypeSpecifier::Decimal64) {
            return Ok(HirType::Float { bits: 64 });
        }
        if specs.contains(&TypeSpecifier::Decimal32) {
            return Ok(HirType::Float { bits: 32 });
        }
        if specs.contains(&TypeSpecifier::Double) {
            return Ok(HirType::Float { bits: 64 });
        }
        if specs.contains(&TypeSpecifier::Float) {
            return Ok(HirType::Float { bits: 32 });
        }
        if specs.contains(&TypeSpecifier::Char) {
            return Ok(HirType::Int {
                signed,
                width: IntWidth::W8,
            });
        }
        let width = Self::integer_width(specs);
        Ok(HirType::Int { signed, width })
    }

    /// Resolves a `struct`/`union`/`enum` tag to a [`HirType::Tag`] or a `typedef` name to a
    /// [`HirType::Named`].
    fn tagged_type(
        &mut self,
        cx: &mut HirContext,
        specs: &[TypeSpecifier],
    ) -> crate::error::Result<Option<HirType>> {
        for spec in specs {
            match spec {
                TypeSpecifier::TypedefName(sym) => {
                    let interned = cx.intern(self.ast.resolve(*sym)?)?;
                    return Ok(Some(HirType::Named(interned)));
                }
                TypeSpecifier::Struct { tag, .. } => {
                    return Ok(Some(self.tag_type(cx, TagKind::Struct, *tag)?));
                }
                TypeSpecifier::Union { tag, .. } => {
                    return Ok(Some(self.tag_type(cx, TagKind::Union, *tag)?));
                }
                TypeSpecifier::Enum { tag, .. } => {
                    return Ok(Some(self.tag_type(cx, TagKind::Enum, *tag)?));
                }
                TypeSpecifier::Atomic(type_name) => {
                    let specifiers = &type_name.specifiers;
                    let derivations = &type_name.declarator.derivations;
                    let ty = self.lower_type(cx, specifiers, derivations)?;
                    return Ok(Some(Self::hir_type_clone(cx, ty)));
                }
                _ => {}
            }
        }
        Ok(None)
    }

    fn hir_type_clone(cx: &HirContext, id: HirTypeId) -> HirType {
        cx.ty(id).clone()
    }

    fn tag_type(
        &self,
        cx: &mut HirContext,
        kind: TagKind,
        tag: Option<stratum_arena::Symbol>,
    ) -> crate::error::Result<HirType> {
        let name = match tag {
            Some(t) => Some(cx.intern(self.ast.resolve(t)?)?),
            None => None,
        };
        Ok(HirType::Tag { kind, name })
    }

    fn wrap_qualifiers(
        cx: &mut HirContext,
        inner: HirTypeId,
        qualifiers: Qualifiers,
    ) -> crate::error::Result<HirTypeId> {
        if qualifiers.is_empty() {
            Ok(inner)
        } else {
            cx.alloc_type(HirType::Qualified { inner, qualifiers })
                .map_err(crate::error::Error::from)
        }
    }

    fn integer_width(specs: &[TypeSpecifier]) -> IntWidth {
        let longs = specs
            .iter()
            .filter(|s| matches!(s, TypeSpecifier::Long))
            .count();
        if longs >= 1 {
            // `long` and `long long` both map to 64-bit in this target-neutral model.
            IntWidth::W64
        } else if specs.contains(&TypeSpecifier::Short) {
            IntWidth::W16
        } else {
            IntWidth::W32
        }
    }
}

/// Builds a [`Qualifiers`] set from a list of C type qualifiers.
fn qualifiers_from(quals: &[TypeQualifier]) -> Qualifiers {
    let mut result = Qualifiers::default();
    for qual in quals {
        match qual {
            TypeQualifier::Const => result.is_const = true,
            TypeQualifier::Volatile => result.is_volatile = true,
            TypeQualifier::Restrict => result.is_restrict = true,
            TypeQualifier::Atomic => result.is_atomic = true,
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{CLowering, qualifiers_from};
    use crate::alloc_prelude::*;
    use crate::test_utils::dump;
    use stratum_c_ast::{
        CAst, DeclSpecifiers, Declarator, Derivation, ParamDecl, TypeQualifier, TypeSpecifier,
    };
    use stratum_hir::{HirContext, HirType, IntWidth, TagKind};

    fn int_specs() -> DeclSpecifiers {
        DeclSpecifiers {
            type_specifiers: vec![TypeSpecifier::Int],
            ..DeclSpecifiers::default()
        }
    }

    #[test]
    fn pointer_and_array_types() {
        let out = dump("void f(void) { int *p; int a[3]; }");
        assert!(out.contains("var p: *i32"), "got: {out}");
        assert!(out.contains("var a: [i32; 3]"), "got: {out}");
    }

    #[test]
    fn array_of_pointers_type() {
        let out = dump("void f(void) { int *a[3]; }");
        assert!(out.contains("var a: [*i32; 3]"), "got: {out}");
    }

    #[test]
    fn qualified_types_are_preserved() {
        let out = dump("void f(void) { const int x; volatile int y; _Atomic int z; }");
        assert!(out.contains("var x: const i32"), "got: {out}");
        assert!(out.contains("var y: volatile i32"), "got: {out}");
        assert!(out.contains("var z: _Atomic i32"), "got: {out}");
    }

    #[test]
    fn c23_decimal_types_lower_to_float_widths() {
        let out = dump("void f(void) { _Decimal32 d32; _Decimal64 d64; _Decimal128 d128; }");
        assert!(out.contains("var d32: f32"), "got: {out}");
        assert!(out.contains("var d64: f64"), "got: {out}");
        assert!(out.contains("var d128: f128"), "got: {out}");
    }

    #[test]
    fn function_returning_pointer_type() {
        let out = dump("int *f(void) { return 0; }");
        assert!(out.contains("-> *i32"), "got: {out}");
    }

    #[test]
    fn unsigned_and_long_widths() {
        let out = dump("void f(void) { unsigned int u; long l; long long ll; short s; char c; }");
        assert!(out.contains("var u: u32"), "got: {out}");
        assert!(out.contains("var l: i64"), "got: {out}");
        assert!(out.contains("var ll: i64"), "got: {out}");
        assert!(out.contains("var s: i16"), "got: {out}");
        assert!(out.contains("var c: i8"), "got: {out}");
    }

    #[test]
    fn function_and_unsized_array_derivations_lower() {
        let ast = CAst::new();
        let mut lowering = CLowering::new(&ast);
        let mut hir = HirContext::new();
        let fn_ty = lowering
            .lower_type(
                &mut hir,
                &int_specs(),
                &[Derivation::Function {
                    params: vec![ParamDecl {
                        specifiers: int_specs(),
                        declarator: Declarator::default(),
                    }],
                    variadic: true,
                }],
            )
            .unwrap();
        assert!(matches!(
            hir.ty(fn_ty),
            HirType::Function { variadic: true, .. }
        ));

        let array_ty = lowering
            .lower_type(&mut hir, &int_specs(), &[Derivation::Array { size: None }])
            .unwrap();
        assert!(matches!(
            hir.ty(array_ty),
            HirType::Array { length: None, .. }
        ));
    }

    #[test]
    fn union_enum_and_typedef_name_types_lower() {
        let mut ast = CAst::new();
        let name = ast.intern("Name").unwrap();
        let alias = ast.intern("Alias").unwrap();
        let mut lowering = CLowering::new(&ast);
        let mut hir = HirContext::new();

        let union_ty = lowering
            .lower_type(
                &mut hir,
                &DeclSpecifiers {
                    type_specifiers: vec![TypeSpecifier::Union {
                        tag: Some(name),
                        fields: None,
                    }],
                    ..DeclSpecifiers::default()
                },
                &[],
            )
            .unwrap();
        assert!(matches!(
            hir.ty(union_ty),
            HirType::Tag {
                kind: TagKind::Union,
                ..
            }
        ));

        let struct_ty = lowering
            .lower_type(
                &mut hir,
                &DeclSpecifiers {
                    type_specifiers: vec![TypeSpecifier::Struct {
                        tag: Some(name),
                        fields: None,
                    }],
                    ..DeclSpecifiers::default()
                },
                &[],
            )
            .unwrap();
        assert!(matches!(
            hir.ty(struct_ty),
            HirType::Tag {
                kind: TagKind::Struct,
                ..
            }
        ));

        let enum_ty = lowering
            .lower_type(
                &mut hir,
                &DeclSpecifiers {
                    type_specifiers: vec![TypeSpecifier::Enum {
                        tag: None,
                        enumerators: None,
                    }],
                    ..DeclSpecifiers::default()
                },
                &[],
            )
            .unwrap();
        assert!(matches!(
            hir.ty(enum_ty),
            HirType::Tag {
                kind: TagKind::Enum,
                name: None
            }
        ));

        let named_ty = lowering
            .lower_type(
                &mut hir,
                &DeclSpecifiers {
                    type_specifiers: vec![TypeSpecifier::TypedefName(alias)],
                    ..DeclSpecifiers::default()
                },
                &[],
            )
            .unwrap();
        assert!(matches!(hir.ty(named_ty), HirType::Named(_)));

        let atomic_ty = lowering
            .lower_type(
                &mut hir,
                &DeclSpecifiers {
                    type_specifiers: vec![TypeSpecifier::Atomic(Box::new(
                        stratum_c_ast::TypeName {
                            specifiers: int_specs(),
                            declarator: Declarator::default(),
                        },
                    ))],
                    ..DeclSpecifiers::default()
                },
                &[],
            )
            .unwrap();
        assert!(matches!(hir.ty(atomic_ty), HirType::Int { .. }));
    }

    #[test]
    fn qualifier_conversion_covers_restrict() {
        let quals = qualifiers_from(&[
            TypeQualifier::Const,
            TypeQualifier::Volatile,
            TypeQualifier::Restrict,
            TypeQualifier::Atomic,
        ]);
        assert!(quals.is_const);
        assert!(quals.is_volatile);
        assert!(quals.is_restrict);
        assert!(quals.is_atomic);
    }

    #[test]
    fn void_bool_and_float_base_types_lower() {
        let ast = CAst::new();
        let mut lowering = CLowering::new(&ast);
        let mut hir = HirContext::new();

        let void = lowering
            .lower_type(
                &mut hir,
                &DeclSpecifiers {
                    type_specifiers: vec![TypeSpecifier::Void],
                    ..DeclSpecifiers::default()
                },
                &[],
            )
            .unwrap();
        assert_eq!(hir.ty(void), &HirType::Void);

        let bool_ty = lowering
            .lower_type(
                &mut hir,
                &DeclSpecifiers {
                    type_specifiers: vec![TypeSpecifier::Bool],
                    ..DeclSpecifiers::default()
                },
                &[],
            )
            .unwrap();
        assert_eq!(hir.ty(bool_ty), &HirType::Bool);

        let double = lowering
            .lower_type(
                &mut hir,
                &DeclSpecifiers {
                    type_specifiers: vec![TypeSpecifier::Double],
                    ..DeclSpecifiers::default()
                },
                &[],
            )
            .unwrap();
        assert_eq!(hir.ty(double), &HirType::Float { bits: 64 });

        let float = lowering
            .lower_type(
                &mut hir,
                &DeclSpecifiers {
                    type_specifiers: vec![TypeSpecifier::Float],
                    ..DeclSpecifiers::default()
                },
                &[],
            )
            .unwrap();
        assert_eq!(hir.ty(float), &HirType::Float { bits: 32 });

        let signed_char = lowering
            .lower_type(
                &mut hir,
                &DeclSpecifiers {
                    type_specifiers: vec![TypeSpecifier::Char],
                    ..DeclSpecifiers::default()
                },
                &[],
            )
            .unwrap();
        assert_eq!(
            hir.ty(signed_char),
            &HirType::Int {
                signed: true,
                width: IntWidth::W8
            }
        );
    }
}
