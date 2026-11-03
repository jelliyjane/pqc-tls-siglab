#include "cats_cti_policy.h"

int main(int argc, char **argv)
{
    struct cats_cti_policy policy;
    if (argc < 3) return 3;
    if (!cats_cti_load(argv[1], (time_t)strtoll(argv[2], NULL, 10), &policy)) return 2;
    for (int i = 3; i < argc; i++)
        printf("%s=%d\n", argv[i], cats_cti_allows(&policy, argv[i]));
    return 0;
}
