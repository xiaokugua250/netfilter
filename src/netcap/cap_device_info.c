//
// Created by liangdu on 20-1-2.
// Author liang.du@nscc-gz.cn
//

#include<stdio.h>
#include<pcap.h>
#include<arpa/inet.h>
#include<string.h>


int main(int argc,char **argv){
    char *device;
    char ip[13]; // ipv4
    char subnet_mask[13]; //ip net mask
    bpf_u_int32     ip_raw ; //ip address
    bpf_u_int32  subnet_mask_raw; //subnet mask as integer
    int lookup_return_code;
    char error_buffer[PCAP_ERRBUF_SIZE]; //size defined in pcap.h
    struct  in_addr address ; // used for both ip & ip subnet

    // first find a device
    device =pcap_lookupdev(error_buffer);
    if (device ==  NULL){
        printf("err in find device,err is %s\n",error_buffer);
        return 1;
    }

    // get device info

    lookup_return_code = pcap_lookupnet(device,&ip_raw,&subnet_mask_raw,error_buffer);
    if (lookup_return_code == -1){
        printf("err in get device info,err is %s\n",error_buffer);
        return  1;
    }
    /*
    If you call inet_ntoa() more than once
    you will overwrite the buffer. If we only stored
    the pointer to the string returned by inet_ntoa(),
    and then we call it again later for the subnet mask,
    our first pointer (ip address) will actually have
    the contents of the subnet mask. That is why we are
    using a string copy to grab the contents while it is fresh.
    The pointer returned by inet_ntoa() is always the same.

    This is from the man:
    The inet_ntoa() function converts the Internet host address in,
    given in network byte order, to a string in IPv4 dotted-decimal
    notation. The string is returned in a statically allocated
    buffer, which subsequent calls will overwrite.
    */

    //get net ip info
    address.s_addr = ip_raw;
    strcpy(ip,inet_ntoa(address));
    if (ip == NULL){
        perror("inet_ntoa"); //print error
        return  1;
    }

    // get subnet mask in human readable form
    address.s_addr = subnet_mask_raw;
    strcpy(subnet_mask,inet_ntoa(address));
    if (subnet_mask == NULL){
     perror("inet_ntoa");
        return 1;
    }
    printf("device is %s\n",device);
    printf("ip address is %s\n",ip);
    printf("Subnet mask is %s\n",subnet_mask);
    return  0;

}