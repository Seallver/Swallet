// network.rs
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::common::params::get_system_params;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::EcPoint;

pub const BUFFER_SIZE: usize = 4096;
pub const MAX_PARTIES: usize = 3;

// 网络消息类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum MessageType {
    Ack = 0,        // ACK
    MsgPublicVk,    // 参与方公布的公钥分片
    MsgPresignData, // 协调器发送的预签名数据
    MsgKeyExchange, // 参与方之间的密钥交换
    MsgUvData,      // 参与方发送的u_i, v_i数据
    RequestSign,    // 签名请求
    MsgPublicR,     // 公开参数R
    SignalOffline,  // 离线情况
    // PAKE 材料
    MsgP2CDelta,
    MsgC2PL,
    MsgP2CM,
    // 签名材料
    MsgC2PCt,
    MsgP2CSigma,
}

impl MessageType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageType::Ack => "ACK",
            MessageType::MsgPublicVk => "MSG_PUBLIC_VK",
            MessageType::MsgPresignData => "MSG_PRESIGN_DATA",
            MessageType::MsgKeyExchange => "MSG_KEY_EXCHANGE",
            MessageType::MsgUvData => "MSG_UV_DATA",
            MessageType::RequestSign => "REQUEST_SIGN",
            MessageType::MsgPublicR => "MSG_PUBLIC_R",
            MessageType::SignalOffline => "SIGNAL_OFFLINE",
            MessageType::MsgP2CDelta => "MSG_P2C_DELTA",
            MessageType::MsgC2PL => "MSG_C2P_L",
            MessageType::MsgP2CM => "MSG_P2C_M",
            MessageType::MsgC2PCt => "MSG_C2P_CT",
            MessageType::MsgP2CSigma => "MSG_P2C_SIGMA",
        }
    }
}

impl From<i32> for MessageType {
    fn from(value: i32) -> Self {
        match value {
            0 => MessageType::Ack,
            1 => MessageType::MsgPublicVk,
            2 => MessageType::MsgPresignData,
            3 => MessageType::MsgKeyExchange,
            4 => MessageType::MsgUvData,
            5 => MessageType::RequestSign,
            6 => MessageType::MsgPublicR,
            7 => MessageType::SignalOffline,
            8 => MessageType::MsgP2CDelta,
            9 => MessageType::MsgC2PL,
            10 => MessageType::MsgP2CM,
            11 => MessageType::MsgC2PCt,
            12 => MessageType::MsgP2CSigma,
            _ => MessageType::Ack, // 默认返回 Ack
        }
    }
}

impl From<MessageType> for i32 {
    fn from(msg_type: MessageType) -> Self {
        match msg_type {
            MessageType::Ack => 0,
            MessageType::MsgPublicVk => 1,
            MessageType::MsgPresignData => 2,
            MessageType::MsgKeyExchange => 3,
            MessageType::MsgUvData => 4,
            MessageType::RequestSign => 5,
            MessageType::MsgPublicR => 6,
            MessageType::SignalOffline => 7,
            MessageType::MsgP2CDelta => 8,
            MessageType::MsgC2PL => 9,
            MessageType::MsgP2CM => 10,
            MessageType::MsgC2PCt => 11,
            MessageType::MsgP2CSigma => 12,
        }
    }
}

// 网络消息结构
#[derive(Debug, Clone)]
pub struct NetworkMessage {
    pub msg_type: MessageType,
    pub src_id: i32,
    pub ack: i32,
    pub data: [u8; 256],
}

impl NetworkMessage {
    pub fn new(msg_type: MessageType, src_id: i32, ack: i32, data: &[u8]) -> Self {
        let mut msg = NetworkMessage {
            msg_type,
            src_id,
            ack,
            data: [0; 256],
        };

        let len = data.len().min(256);
        msg.data[..len].copy_from_slice(&data[..len]);

        msg
    }

    pub fn empty() -> Self {
        NetworkMessage {
            msg_type: MessageType::Ack,
            src_id: 0,
            ack: 0,
            data: [0; 256],
        }
    }
}

// 消息处理回调函数类型
pub type MessageHandler = Box<dyn Fn(&NetworkMessage) + Send + Sync + 'static>;

// 全局监听线程退出标志
pub static LISTEN_THREAD_EXIT: AtomicBool = AtomicBool::new(false);

// 序列化/反序列化函数
pub fn serialize_bn(bn: &BigNum) -> [u8; 32] {
    let mut buffer = [0u8; 32];

    // 使用 unwrap_or 提供默认值
    let bytes = bn.to_vec();
    let bn_size = bytes.len().min(32);
    buffer[(32 - bn_size)..].copy_from_slice(&bytes[..bn_size]);

    buffer
}

pub fn deserialize_bn(buffer: &[u8; 32]) -> Result<BigNum, openssl::error::ErrorStack> {
    BigNum::from_slice(buffer)
}

pub fn serialize_ec_point(point: &EcPoint) -> Result<String, openssl::error::ErrorStack> {
    let params = get_system_params();
    let group = &params.group;
    let mut ctx = BigNumContext::new()?;

    // 使用压缩格式
    let point_bytes = point.to_bytes(
        group,
        openssl::ec::PointConversionForm::COMPRESSED,
        &mut ctx,
    )?;

    // 转换为十六进制字符串
    Ok(hex::encode(point_bytes))
}

pub fn deserialize_ec_point(hex_str: &str) -> Result<EcPoint, openssl::error::ErrorStack> {
    let params = get_system_params();
    let group = &params.group;
    let mut ctx = BigNumContext::new()?;

    // 从十六进制解码
    let point_bytes = hex::decode(hex_str).map_err(|_| openssl::error::ErrorStack::get())?;

    // 从字节创建点
    EcPoint::from_bytes(group, &point_bytes, &mut ctx)
}

// 发送消息函数
pub fn send_message(
    src_id: i32,
    ip: &str,
    port: u16,
    msg_type: MessageType,
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    const MAX_RETRY: usize = 10;

    for retry in 0..MAX_RETRY {
        // 解析 IP 地址
        let ip_addr = match ip.parse::<IpAddr>() {
            Ok(addr) => addr,
            Err(_) => {
                eprintln!("Invalid IP address: {}", ip);
                return Err("Invalid IP address".into());
            }
        };

        let addr = SocketAddr::new(ip_addr, port);

        // 连接超时设置
        let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            Ok(stream) => stream,
            Err(e) => {
                eprintln!("Connection failed (attempt {}): {}", retry + 1, e);
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        };

        // 设置读写超时
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        stream.set_write_timeout(Some(Duration::from_secs(1)))?;

        // 创建消息
        let msg = NetworkMessage::new(msg_type, src_id, 0, data);

        // 序列化消息
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&(msg.msg_type as i32).to_be_bytes());
        buffer.extend_from_slice(&msg.src_id.to_be_bytes());
        buffer.extend_from_slice(&msg.ack.to_be_bytes());
        buffer.extend_from_slice(&msg.data);

        // 发送消息
        if let Err(e) = stream.write_all(&buffer) {
            eprintln!("Send failed (attempt {}): {}", retry + 1, e);
            thread::sleep(Duration::from_secs(1));
            continue;
        }

        // 等待 ACK
        let mut ack_buffer = [0u8; std::mem::size_of::<i32>() * 3 + 256];
        match stream.read_exact(&mut ack_buffer) {
            Ok(_) => {
                // 解析 ACK 消息
                let recv_msg_type = i32::from_be_bytes([
                    ack_buffer[0],
                    ack_buffer[1],
                    ack_buffer[2],
                    ack_buffer[3],
                ]);
                let ack = i32::from_be_bytes([
                    ack_buffer[8],
                    ack_buffer[9],
                    ack_buffer[10],
                    ack_buffer[11],
                ]);

                if MessageType::from(recv_msg_type) == MessageType::Ack && ack == 1 {
                    println!(
                        "[+] Sent message and received ACK from party {}:{} \t MESSAGE TYPE: {}",
                        ip,
                        port,
                        MessageType::from(msg_type).as_str()
                    );
                    return Ok(());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // 非阻塞错误，等待后重试
                if retry < 4 {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                } else {
                    return Err("Timeout waiting for ACK".into());
                }
            }
            Err(e) => {
                return Err(e.into());
            }
        }

        thread::sleep(Duration::from_secs(1));
    }

    Err("Failed to send message after retries".into())
}

// 广播消息
pub fn broadcast(msg_type: MessageType, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let params = get_system_params();
    let self_id = params.current_party_id;

    for (id, party) in params.parties.iter().enumerate() {
        if id as i32 == self_id {
            continue;
        }

        // 尝试发送，但不失败就继续
        if let Err(e) = send_message(self_id, &party.ip, party.port as u16, msg_type, data) {
            eprintln!("Failed to send to party {}: {}", id, e);
        }
    }

    Ok(())
}

// 网络服务管理器
pub struct NetworkService {
    message_handler: Arc<Mutex<Option<MessageHandler>>>,
    listen_thread: Option<thread::JoinHandle<()>>,
}

impl NetworkService {
    pub fn new() -> Self {
        NetworkService {
            message_handler: Arc::new(Mutex::new(None)),
            listen_thread: None,
        }
    }

    pub fn set_message_handler(&mut self, handler: MessageHandler) {
        *self.message_handler.lock().unwrap() = Some(handler);
    }

    pub fn start_listen_thread(&mut self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let message_handler = self.message_handler.clone();

        let handle = thread::spawn(move || {
            listen_thread_impl(port, message_handler);
        });

        self.listen_thread = Some(handle);
        Ok(())
    }

    pub fn stop(&mut self) {
        LISTEN_THREAD_EXIT.store(true, Ordering::SeqCst);

        if let Some(handle) = self.listen_thread.take() {
            let _ = handle.join();
        }
    }
}

// 监听线程实现
fn listen_thread_impl(port: u16, message_handler: Arc<Mutex<Option<MessageHandler>>>) {
    let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("Failed to bind to port {}: {}", port, e);
            return;
        }
    };

    listener.set_nonblocking(true).unwrap_or_default();

    println!("[*] Listening on port {}...", port);

    while !LISTEN_THREAD_EXIT.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, addr)) => {
                // 设置读取超时
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap_or_default();

                // 读取消息
                let mut buffer = [0u8; std::mem::size_of::<i32>() * 3 + 256];
                match stream.read_exact(&mut buffer) {
                    Ok(_) => {
                        // 解析消息
                        let msg_type =
                            i32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
                        let src_id =
                            i32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
                        let ack =
                            i32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);
                        let data = &buffer[12..268];

                        let msg = NetworkMessage {
                            msg_type: MessageType::from(msg_type),
                            src_id,
                            ack,
                            data: data.try_into().unwrap_or([0; 256]),
                        };

                        // 发送 ACK
                        if ack == 0 {
                            let ack_msg = NetworkMessage::new(
                                MessageType::Ack,
                                get_system_params().current_party_id,
                                1,
                                &[],
                            );

                            let mut ack_buffer = Vec::new();
                            ack_buffer.extend_from_slice(&(ack_msg.msg_type as i32).to_be_bytes());
                            ack_buffer.extend_from_slice(&ack_msg.src_id.to_be_bytes());
                            ack_buffer.extend_from_slice(&ack_msg.ack.to_be_bytes());
                            ack_buffer.extend_from_slice(&ack_msg.data);

                            let _ = stream.write_all(&ack_buffer);
                        }

                        println!(
                            "[+] Received message from party {} \t\t\t\t MESSAGE TYPE: {}",
                            src_id,
                            msg.msg_type.as_str()
                        );

                        // 调用消息处理器
                        if let Some(handler) = message_handler.lock().unwrap().as_ref() {
                            handler(&msg);
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to read message from {}: {}", addr, e);
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => {
                eprintln!("Accept error: {}", e);
            }
        }
    }

    println!("[*] Listen thread on port {} stopped", port);
}

impl Drop for NetworkService {
    fn drop(&mut self) {
        self.stop();
    }
}

// 测试模块
#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::crypto_utils;
    #[test]
    fn test_serialize_deserialize_bn() {
        let bn = BigNum::from_u32(1234567890).unwrap();
        let serialized = serialize_bn(&bn);
        let deserialized = deserialize_bn(&serialized).unwrap();

        assert_eq!(bn, deserialized);
    }

    #[test]
    fn test_serialize_deserialize_ec_point() {
        let params = get_system_params();
        let group = &params.group;

        // 生成随机点
        let point = crypto_utils::random_in_group().unwrap();

        let serialized = serialize_ec_point(&point).unwrap();
        let deserialized = deserialize_ec_point(&serialized).unwrap();

        // 验证点是否相等
        let mut ctx = BigNumContext::new().unwrap();
        assert!(point.eq(group, &deserialized, &mut ctx).unwrap_or(false));
    }

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(MessageType::Ack as i32, 0);
        assert_eq!(MessageType::from(0), MessageType::Ack);

        assert_eq!(MessageType::MsgPublicVk as i32, 1);
        assert_eq!(MessageType::from(1), MessageType::MsgPublicVk);

        // 测试字符串表示
        assert_eq!(MessageType::Ack.as_str(), "ACK");
        assert_eq!(MessageType::MsgPublicVk.as_str(), "MSG_PUBLIC_VK");
    }

    #[test]
    fn test_network_message() {
        let data = b"Test data";
        let msg = NetworkMessage::new(MessageType::RequestSign, 1, 0, data);

        assert_eq!(msg.msg_type, MessageType::RequestSign);
        assert_eq!(msg.src_id, 1);
        assert_eq!(msg.ack, 0);
        assert_eq!(&msg.data[..9], data);
    }
}
