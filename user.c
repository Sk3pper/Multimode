#include "multimode_ioctl.h"
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
int input_int(){
	long res = -1;
	while(1){
		char* p;
		char* buff = NULL;
		int size = 0;
		if(getline(&buff, (size_t *)&size,stdin) > 1 && buff[0] != '\n'){
			res=strtol(buff, &p, 0); //se faccio overflow negativo su long, strtol ritorna MIN_LONG
						 //se faccio overloow positivo su long, strtol ritorna MAX_LONG
			int test = (int) res;
			if(res != (long) test){
				printf("overflow on int. Retry...\n");	
				continue;			
			}
			if(*p == '\n' || *p == '\0'){
				if(res > 0)				
					break;
				else
					printf("do not insert negative number or 0!\n");
			}
			else
				printf("the input is not recognized as an integer. Retry...\n");
		}
		else
			printf("empty string found. Insert a number\n");
	}
	return (int)res;
}
int input(char* in,int n){
	int res;
	while(1){
		char* line = NULL;
		int size = 0;
		res=getline(&line,(size_t *)&size,stdin);
		//printf("line : %s ret : %d strlen : %d\n",line,(int)res,(int)strlen(line));
		if(line[0] != '\n' && res<=n+1 && res >1){
			/*res--;
			in[res]='\0';*/ //messe prima di strcpy non si sa per quale motivo non sovrascrivono \n
			strcpy(in,line);
			res--;
			in[res]='\0';
			free(line);
			break;
		}
		else
			printf("error : number of characters exceeded or null string is inserted.\n");
	}
	return 0;

}
int write_operation(int fd){
	char buffer[1025]; //1024 bytes + '/0'
	printf("what string do you want to write? ");
	input(buffer,1025);
	//printf("string = %s - strlen(string)=%d\n",buffer,(int)strlen(buffer));
	int wrote = write(fd, buffer, strlen(buffer));
    	if (wrote < 0){
        	//printf("There was an error writing to multimode0; wrote: %d\n", wrote);
        	return -1;
    	}
	return 0;
}
int set_packet_mode(int fd){
	int res;
	if(ioctl(fd,MULTIMODE_SET_PACKET,&res)==-1)
		return -1;
	else
		return 0;
}
int set_stream_mode(int fd){
	int res;
	if(ioctl(fd,MULTIMODE_SET_STREAM,&res)==-1)
		return -1;
	else
		return 0;
}
int set_blocking_mode(int fd){
	int res;
	if(ioctl(fd,MULTIMODE_SET_BLOCKING,&res)==-1)
		return -1;
	else
		return 0;
}
int set_notblocking_mode(int fd){
	int res;
	if(ioctl(fd,MULTIMODE_SET_NOTBLOCKING,&res)==-1)
		return -1;
	else
		return 0;
}
int set_buffer_size(int fd){
	int new_size;
	printf("new size = ");
	new_size=input_int();
	if(ioctl(fd,MULTIMODE_SET_LINKED_LIST_SIZE,&new_size)==-1)
		return -1;	
	else
		printf("size set to : %d\n",new_size);
	return 0;
}
int get_buffer_size(int fd){
	int size;
	if(ioctl(fd,MULTIMODE_GET_LINKED_LIST_SIZE,&size)==-1)
		return -1;
	else
		printf("size get : %d\n",size);
	return 0;
}
int set_packet_max_size(int fd){
	int new_size;
	printf("new size = ");
	new_size=input_int();
	if(ioctl(fd,MULTIMODE_SET_PACKET_MAX_SIZE,&new_size)==-1)
		return -1;	
	else
		printf("maximum packet size set to : %d\n",new_size);
	return 0;
}
int get_packet_max_size(int fd){
	int size;
	if(ioctl(fd,MULTIMODE_GET_PACKET_MAX_SIZE,&size)==-1)
		return -1;
	else
		printf("maximum packet size get : %d\n",size);
	return 0;
}
int set_packet_min_size(int fd){
	int new_size;
	printf("new size = ");
	new_size=input_int();
	if(ioctl(fd,MULTIMODE_SET_PACKET_MIN_SIZE,&new_size)==-1)
		return -1;	
	else
		printf("minimum packet size set to : %d\n",new_size);
	return 0;
}
int get_packet_min_size(int fd){
	int size;
	if(ioctl(fd,MULTIMODE_GET_PACKET_MIN_SIZE,&size)==-1)
		return -1;
	else
		printf("minimum packet size get : %d\n",size);
	return 0;
}
int read_operation(int fd){
	int dim=0;
	int res=0;
	printf("how many bytes do you want to read? ");
	dim = input_int();
	char data[dim+1];
	res=read(fd, data,dim);
	if( res < 0 )
		return -1;
	data[res]='\0';
	printf("read data: %s\n", data);
	return 0;
}
int ioctl_operation(int fd){
	int choice;
	printf("1) set packet mode\n");
	printf("2) set stream mode\n");
	printf("3) set blocking mode\n");
	printf("4) set not-blocking mode\n");
	printf("5) set FIFO queue size\n");
	printf("6) get FIFO queue size\n");
	printf("7) set packet min size\n");
	printf("8) set packet max size\n");
	printf("9) get packet min size\n");
	printf("10)get packet max size\n");
	choice = input_int();
	switch(choice){
		case 1 : 
			if(set_packet_mode(fd)==-1)
				return -1;
			else
				printf("packet mode is set\n");
			break;
		case 2 : 
			if(set_stream_mode(fd)==-1)
				return -1;
			else
				printf("stream mode is set\n");
			break;
		case 3 : 
			if(set_blocking_mode(fd)==-1)
				return -1;
			else
				printf("blocking mode is set\n");
			break;
		case 4 : 
			if(set_notblocking_mode(fd)==-1)
				return -1;
			else
				printf("not blocking mode is set\n");
			break;	
		case 5 :
			if(set_buffer_size(fd)==-1)
				return -1;
			break;
		case 6 :
			if(get_buffer_size(fd)==-1)
				return -1;
			break;
		case 7 :
			if(set_packet_min_size(fd)==-1)
				return -1;
			break;
		case 8 :
			if(set_packet_max_size(fd)==-1)
				return -1;
			break;
		case 9 :
			if(get_packet_min_size(fd)==-1)
				return -1;
			break;
		case 10 :
			if(get_packet_max_size(fd)==-1)
				return -1;
			break;
		default : printf("error ioctl choice\n");
			break;	
	}
	return 0;
}
int main(int argc, char* argv[]){
	if (argc < 2){
		printf("main usage: %s minor\n", argv[0]);
		return -1;
	}
	char * minor = argv[1];
	char * file_name = "/dev/FIFOQueue";
	char device [strlen(file_name)+1];
	int choice;
	strcpy(device, file_name);
	strcat(device, minor);
	int filedesc = open(device, O_RDWR);
    	if (filedesc < 0) {
		printf("There was an error opening FIFOQueue%s\n",minor);
        	return -1;
    	}
	printf("MULTIMODE DEVICE FILE SHELL\n");
	printf("Choose one of the following operation :\n");
	printf("1)write\n");
	printf("2)read\n");
	printf("3)ioctl\n");
	printf("4)exit\n");
	choice = input_int();
	while(choice!=4){
		switch(choice){
			case 1 :
				if(write_operation(filedesc)==-1){
					printf("There was an error on write : ");
					if(errno == EAGAIN)
						printf("there is no enough space to write in the buffer, the buffer is full.\n");
					if(errno == EINVAL){
						printf("\n1)the number of bytes that you want to write are lower than the minimum packet size.\n");
						printf("2)the number of bytes that you want to write are greater than the maximum packet size.\n");
						printf("3)there was an error in the copy from user.\n");
					}
				}				
				break;
			case 2 :
				if(read_operation(filedesc)==-1){
					printf("There was an error on read : ");
					if(errno == EAGAIN)
						printf("the buffer is empty\n");
					if(errno == EINVAL){
						printf("\n1)the number of bytes that you want to read are lower or equal than 0\n");
						printf("3)there was an error in the copy_to_user\n");
					}
				}
				break;
			case 3 :
				system("clear");
				if(ioctl_operation(filedesc)==-1){
					printf("There was an error on ioctl\n");
				}
				break;
			default : 
				fprintf(stderr,"invalid choice\n");
				break;
		}
		printf("Press enter to continue...");
		getchar();
		system("clear");
		printf("MULTIMODE DEVICE FILE SHELL\n");
		printf("Choose one of the following operation :\n");
		printf("1)write\n");
		printf("2)read\n");
		printf("3)ioctl\n");
		printf("4)exit\n");
		choice = input_int();
	}
    	close(filedesc);
	return 0;
}
