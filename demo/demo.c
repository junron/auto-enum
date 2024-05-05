#include <stdio.h>
#include <seccomp.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <seccomp.h>
#include <stddef.h>
#include<sys/socket.h>
#include<arpa/inet.h>


struct sock_filter filter[] = {
    BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_read, 1, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_write, 0, 1),
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
};

struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
};

struct sockaddr_in server = {
    .sin_family = AF_INET,
    .sin_addr.s_addr = INADDR_ANY,
    .sin_port = 14597,
};
int main() {
    void* region = mmap(NULL, 
			0x1000,
			PROT_WRITE | PROT_EXEC | PROT_READ,
			MAP_ANONYMOUS | MAP_PRIVATE,
			-1,
			0);

    int socket_desc , client_sock , c;
    struct sockaddr_in client;
     
    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        return 1;
    }
     
    //Bind
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        return 1;
    }
     
    listen(socket_desc , 3);
     
    c = sizeof(struct sockaddr_in);
	
    client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);

    int recv_len = recv(client_sock, region, 0x1000, 0);
    printf("Received %d bytes!\n", recv_len);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        return 1;
    }
    if (prctl(PR_SET_SECCOMP, 2, &prog)) {
        return 1;
    }

    ((int(*)())region)();

    return 0;
}