use std::net::TcpListener;
use std::io::{Read, Write};
use std::thread;

pub fn start_dummy_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    
    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                let mut buffer = [0; 1024];
                let _ = stream.read(&mut buffer);
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
                let _ = stream.write_all(response.as_bytes());
            }
        }
    });
    
    format!("http://127.0.0.1:{}", port)
}
