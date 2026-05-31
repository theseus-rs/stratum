int main(void) {
    int i;
    int sum;
    sum = 0;
    for (i = 0; i < 10; i = i + 1) {
        sum = sum + i;
    }
    if (sum) {
        return sum;
    } else {
        return 0;
    }
}
