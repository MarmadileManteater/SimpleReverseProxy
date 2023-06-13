use actix_web::{middleware,App, HttpServer, web::{self, Bytes}};
use actix_cors::Cors;
use rustls::PrivateKey;
use rustls_pemfile::pkcs8_private_keys;
use rustls::Certificate;
use rustls_pemfile::certs;
use std::fs::File;
use std::io::BufReader;
use rustls::ServerConfig;
use actix_web::{HttpResponse, HttpRequest};
use reqwest::{Client, header::{HeaderMap}};
use actix_web::http::StatusCode;
use std::env;
use std::fs;
use std::collections::HashMap;
use regex::Regex;
use std::str::FromStr;
use serde::{Deserialize, Serialize};

const DEFAULT_PORT : &str = "8080";
const DEFAULT_DIRECTORY : &str = "public";
const DEFAULT_ERROR_PAGE : &str = "404.html";
const DEFAULT_INDEX_PAGE : &str = "index.html";

#[derive(Debug, Deserialize, Serialize, Clone)]
struct ProxyMap {
  protocol: String,
  uri: String,
  port: Option<String>
}

// 🦴 Retrieves proxy maps from a JSON file given the path
fn retrieve_proxy_maps(json_file: String) -> HashMap<String, ProxyMap> {
  match fs::read_to_string(json_file) {
    Ok(data) => {
      match serde_json::from_str::<HashMap<String, ProxyMap>>(&data) {
        Ok(proxy_maps) => proxy_maps,
        Err(_) => {
          HashMap::new()
        }
      }
    },
    Err(_) => {
      HashMap::new()
    }
  }
}

// Convert a proxy map into a URI
fn proxy_map_to_uri(proxy_map: ProxyMap) -> String {
  match proxy_map.port {
    // If proxy map has a port: format it like this,
    Some(port) => format!("{}://{}:{}", proxy_map.protocol, proxy_map.uri, port),
    None => {
      // If the proxy map does not have a port,
      if proxy_map.protocol == "file" {
        // Don't include the port for file protocol
        format!("{}://{}", proxy_map.protocol, proxy_map.uri)
      } else {
        // Always include the default port for any other protocol
        format!("{}://{}:{}", proxy_map.protocol, proxy_map.uri, DEFAULT_PORT)
      }
    }
  }
}

// Simple passthrough for subdomains listed in the passed proxymaps json
pub async fn local_proxy(
  input_url: web::Path<String>,
  req: HttpRequest,
  bytes: Bytes
)  -> HttpResponse {
  let args: Vec<String> = env::args().collect();
  let default_maps = HashMap::new();
  let proxy_maps = if args.len() > 3 {
    retrieve_proxy_maps(args[3].clone())
  } else {
    default_maps
  };
  // The request URI
  let uri = String::from(format!("{}", req.connection_info().host()));
  // The request subdomain (defaults to '.')
  let subdomain = match Regex::new(r#"([a-zA-Z]*?)\.[a-zA-Z]*?\."#).unwrap().captures(&uri) {
    Some(result) => {
      match result.get(1) {
        Some(group) => group.as_str(),
        None => "."
      }
    },
    None => "."
  };
  // The URI for the underlying service to be provided
  let service_url = if proxy_maps.contains_key(subdomain) {
    // If the subdomain is mapped,
    let proxy_map = proxy_maps[subdomain].clone();
    proxy_map_to_uri(proxy_map)
  } else {
    if proxy_maps.contains_key(".") {
      // If the subdomain is not mapped (or this is the root domain),
      proxy_map_to_uri(proxy_maps["."].clone())
    } else {
      String::from("file://.")
    }
  };
  let url = format!("{}/{}", service_url, input_url);
  // TODO ✏ properly implement logging
  println!("Accessing URL: {}", url);
  if url.ends_with("/") && input_url.len() > 0 {
    // ↩Redirect urls that trail with slashes
    let modified_url : String = input_url.chars().take(input_url.len() -1).collect();
    HttpResponse::build(StatusCode::from_u16(301).unwrap()).insert_header(("Location", format!("/{}", modified_url))).body(web::Bytes::from(""))
  } else {
    // Routing
    if url.starts_with("file://") {
      // 📁Filesystem URIs (will always treat public/ as the root)
      let mut status_code = 200;
      let path = &url[7..url.len()];
      let data = match fs::read(format!("{}/{}", DEFAULT_DIRECTORY, path)) {
        Ok(data) => data,
        Err(_) => {
          let format_string = if path.ends_with("/") {
            String::from(DEFAULT_INDEX_PAGE)
          } else {
            format!("/{}", DEFAULT_INDEX_PAGE)
          };
          match fs::read(format!("{}/{}{}", DEFAULT_DIRECTORY, path, format_string)) {
            Ok(file_data) => file_data,
            Err(_) => {
              // TODO ✏ add error logging
              status_code = 404;
              match fs::read(format!("{}/{}/{}", DEFAULT_DIRECTORY, &service_url[7..service_url.len()], DEFAULT_ERROR_PAGE)) {
                Ok(response_data) => response_data,
                Err(_) => {
                  fs::read(format!("{}/{}", DEFAULT_DIRECTORY, DEFAULT_ERROR_PAGE)).unwrap()
                }
              }
            }
          }
        }
      };
      let content_type = match mime_guess::from_path(path).first() {
        Some(value) => format!("{}", value),
        None => String::from("text/html")
      };
      HttpResponse::build(StatusCode::from_u16(status_code).unwrap()).insert_header(("content-type", content_type)).body(web::Bytes::from(data))
    } else {
      let client = match Client::builder()
        // we don't want reqwest to automatically handle our redirects
        .redirect(reqwest::redirect::Policy::none())
        .build() {
          Ok(client) => client,
          Err(error) => {
            return HttpResponse::build(StatusCode::from_u16(500).unwrap()).content_type("application/json").body(format!("{{ \"error\": \"Failed to build reqwest client.\", \"message\": \"{:?}\" }}", error));
          }
        };
      let mut headers = HeaderMap::new();
      
      for (header_name, header_value) in req.headers().into_iter() {
        headers.insert(header_name, header_value.into());
      };

      
      let url = format!("{}?{}", &url, req.query_string());
      match client.request(req.method().into(), &url).body(bytes).send().await {
        Ok(response) => {
          let response_code = response.status().as_u16();
          let mut builder = HttpResponse::build(StatusCode::from_u16(response_code).unwrap());
          for (header_name, header_value) in response.headers() {
            // don't remove this line because it causes a bug in ff🦊
            if header_name != "content-length" {
              builder.insert_header((header_name, header_value.to_str().unwrap()));
            }
          }
          builder.streaming(response.bytes_stream())
        },
        Err(error) => {
          HttpResponse::build(StatusCode::from_u16(500).unwrap()).content_type("application/json").body(format!("{{ \"type\": \"error\", \"message\": \"Fatal error when connecting to server {}\", \"inner_error\": \"{}\" }}", service_url, format!("{:?}", error).replace("\"", "\\\"")))
        }
      }
    }
  }
}

// Code taken from : https://prestonfrom.com/how_to_ssl.html
// i'm not sure how to reference it as far as licensing is concerned, 
// but hopefully I am okay because it is a tutorial which
// references an official actix example for this code
fn load_certs(cert: &str, key: &str) -> Result<ServerConfig, String> {
  let cert_file = &mut BufReader::new(File::open(&cert).map_err(|e| e.to_string())?);
  let key_file = &mut BufReader::new(File::open(&key).map_err(|e| e.to_string())?);
  
  let cert_chain = certs(cert_file)
    .map_err(|e| e.to_string())?
    .into_iter()
    .map(Certificate)
    .collect();
  let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
    .map_err(|e| e.to_string())?
    .into_iter()
    .map(PrivateKey)
    .collect();
  
  if keys.is_empty() {
    return Err("Could not locate PKCS 8 private keys.".to_string());
  }
  
  let config = ServerConfig::builder().with_safe_defaults().
  with_no_client_auth();
  config.with_single_cert(cert_chain, keys.remove(0)).map_err(|e| e.to_string())
}


#[actix_rt::main]
async fn main() -> std::io::Result<()> {
  let args: Vec<String> = env::args().collect();
  if args.len() > 2 {
    let path_to_cert = String::from(&args[1]);
    let path_to_private_key = String::from(&args[2]);
    let num_of_workers = if args.len() > 3 {
      i32::from_str(&args[3]).unwrap_or(1)
    } else {
      1
    };
    let certs = load_certs(&path_to_cert, &path_to_private_key).unwrap();
      HttpServer::new(move || {
          App::new()
            .wrap(middleware::Compress::default())
            .service(web::resource("/{url:.*}").route(web::route().to(local_proxy)))
            .wrap(
              Cors::permissive()
            )
      })
      .bind_rustls(format!("{}:{}", "0.0.0.0".to_string(), "443".to_string()), certs)?
      .workers(num_of_workers as usize)
      .run()
      .await
  } else {
    println!("Two arguments are required: path_to_cert, path_to_private_key");
    Ok(())
  }
}
