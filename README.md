# http-timings: A library to measure HTTP timings
Inspired by the libraries [TTFB](https://github.com/phip1611/ttfb) by [phip1611](https://github.com/phip1611) and [ssl-expiration](https://github.com/onur/ssl-expiration) by [onur](https://github.com/onur). This library provides the following information from any given URL:
- Status code
- Body of the response
- SSL Certificate information
- DNS Lookup Time
- TCP Connection Time
- TLS Handshake Time
- HTTP Send Time
- Time to First Byte
- Content Download Time

## Usage
```rust
use http_timings::from_string;

let url = "https://www.example.com";
let timeout = Some(Duration::from_secs(5)); // Set a timeout of 5 seconds
match from_string(url, timeout) {
    Ok(response) => {
        println!("Response Status: {}", response.status);
        println!("Response Body: {}", response.body);
        if let Some(cert_info) = response.certificate_information {
            println!("Certificate Subject: {:?}", cert_info.subject);
            println!("Certificate Issued At: {:?}", cert_info.issued_at);
            println!("Certificate Expires At: {:?}", cert_info.expires_at);
            println!("Is Certificate Active: {:?}", cert_info.is_active);
        } else {
            println!("No certificate information available.");
        }
    },
    Err(e) => {
        eprintln!("Error occurred: {:?}", e);
    }
}
```

The `Response` struct provides all the information about the request. The timings in both relative and total terms. The relative timings are the time taken for each step of the request, while the total timings are the time taken from the start of the request to the end of the request.

The URL input can be any valid website as well as any valid IP.