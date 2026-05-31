#define SQUARE(x) ((x) * (x))
#define LIMIT 5

int compute(int n) {
    int total;
    total = SQUARE(n) + LIMIT;
    return total;
}
