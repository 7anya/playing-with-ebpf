#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <fcntl.h>

#define RING_BUFFER_PAGES 64
typedef unsigned long long u64;
typedef unsigned int u32;

struct fault_data_t {
    u64 faulted_address;
    u32 pid;
};

int handle_event(void *ctx, void *data, size_t data_sz) {
    struct fault_data_t *event = data;
    printf("Faulted Address: 0x%llx, PID: %d\n", event->faulted_address, event->pid);
    return 0;
}

int main() {
    struct bpf_object *obj;
    struct ring_buffer *rb = NULL;
    int map_fd, epoll_fd, ring_fd, err;
    struct epoll_event event, events[1];

    obj = bpf_object__open_file("prog.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "fentry/handle_mm_fault");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        return 1;
    }

    struct bpf_link *link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "Failed to attach BPF program\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "ringbuf");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find ringbuf map\n");
        return 1;
    }

    // Set up the ring buffer
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    // Get the ring buffer's internal file descriptor for epoll
    ring_fd = ring_buffer__epoll_fd(rb);

    // Create epoll instance
    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        return 1;
    }

    // Add the ring buffer fd to the epoll instance
    event.events = EPOLLIN;
    event.data.fd = ring_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ring_fd, &event) < 0) {
        perror("epoll_ctl");
        return 1;
    }

    printf("eBPF program successfully attached! Listening for events...\n");

    // Wait for events using epoll
    while (1) {
        int n = epoll_wait(epoll_fd, events, 1, -1);
        if (n < 0) {
            if (errno == EINTR) {
                continue;  // Interrupted by signal, retry
            }
            perror("epoll_wait");
            break;
        }

        // Consume all available entries in the ring buffer
        err = ring_buffer__consume(rb);
        if (err < 0) {
            fprintf(stderr, "Error consuming ring buffer: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    close(epoll_fd);
    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}
