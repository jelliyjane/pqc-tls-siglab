#include <assert.h>
#include "tcp_selection_window.h"

int main(void)
{
    assert(tcp_selection_window(10, 1460, 65535) == 14600);
    assert(tcp_selection_window(10, 1460, 4096) == 4096);
    assert(tcp_selection_window(10, 1460, 14600) == 14600);
    assert(tcp_selection_window(10, 1460, 0) == 0);
    assert(tcp_selection_window(0, 1460, 65535) == -1);
    assert(tcp_selection_window(10, 0, 65535) == -1);
    assert(tcp_selection_window(UINT32_MAX, UINT32_MAX, 65535) == 65535);
    return 0;
}
