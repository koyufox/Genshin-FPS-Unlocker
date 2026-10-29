extern int rust_control(const char *command, const char *module);

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    return rust_control(argv[1], argv[2]);
}
