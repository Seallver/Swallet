// keygen.rs
use crate::common::network::{deserialize_ec_point, MessageType, NetworkMessage, NetworkService};
use crate::common::params::get_system_params;
use crate::common::{self, crypto_utils};
use openssl::bn::BigNumContext;
use openssl::ec::EcPoint;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
// 全局状态
pub struct KeygenState {
    pub vk: Arc<Mutex<Option<EcPoint>>>,
    pub vk_received_count: Arc<Mutex<usize>>,
}

impl KeygenState {
    pub fn new() -> Self {
        KeygenState {
            vk: Arc::new(Mutex::new(None)),
            vk_received_count: Arc::new(Mutex::new(0)),
        }
    }
}

// 消息处理器
pub fn create_keygen_handler(
    state: Arc<KeygenState>,
) -> Box<dyn Fn(&NetworkMessage) + Send + Sync + 'static> {
    Box::new(move |msg: &NetworkMessage| {
        keygen_message_handler(msg, Arc::clone(&state));
    })
}

fn keygen_message_handler(msg: &NetworkMessage, state: Arc<KeygenState>) {
    match msg.msg_type {
        MessageType::MsgPublicVk => {
            match handle_public_vk(msg, &state) {
                Ok(should_stop) => {
                    if should_stop {
                        // 设置退出标志
                        crate::common::network::LISTEN_THREAD_EXIT.store(true, Ordering::SeqCst);
                    }
                }
                Err(e) => {
                    eprintln!("Error handling public VK: {:?}", e);
                }
            }
        }
        _ => {
            println!(
                "Received unexpected message type in keygen phase: {}",
                msg.msg_type.as_str()
            );
        }
    }
}

fn handle_public_vk(
    msg: &NetworkMessage,
    state: &KeygenState,
) -> Result<bool, Box<dyn std::error::Error>> {
    let params = get_system_params();
    let group = &params.group;
    let mut ctx = BigNumContext::new()?;

    // 反序列化 VK_i
    let vk_i_hex = String::from_utf8_lossy(&msg.data)
        .trim_matches('\0')
        .to_string();

    let vk_i = deserialize_ec_point(&vk_i_hex)?;

    // 更新全局 VK
    let mut vk_lock = state.vk.lock().unwrap();
    let mut count_lock = state.vk_received_count.lock().unwrap();

    match &mut *vk_lock {
        Some(vk) => {
            // 累加 VK
            let mut sum = EcPoint::new(group)?;
            sum.add(group, vk, &vk_i, &mut ctx)?;
            *vk = sum;
        }
        None => {
            // 第一个收到的 VK_i
            *vk_lock = Some(vk_i);
        }
    }

    *count_lock += 1;

    // 检查是否收到所有参与方的 VK
    if *count_lock >= common::params::NUM_PARTIES {
        return Ok(true); // 应该停止监听
    }

    Ok(false) // 继续监听
}

// 接收 VK 的主函数
pub fn recv_vk(port: u16) -> Result<EcPoint, Box<dyn std::error::Error>> {
    let state = Arc::new(KeygenState::new());
    let state_clone = Arc::clone(&state);

    // 创建网络服务
    let mut network_service = NetworkService::new();

    // 设置消息处理器
    let handler = create_keygen_handler(state_clone);
    network_service.set_message_handler(handler);

    // 启动监听线程
    network_service.start_listen_thread(port)?;

    println!("[*] Coordinator started, waiting for public VK from parties...");

    // 等待接收所有 VK
    loop {
        {
            if crate::common::network::LISTEN_THREAD_EXIT.load(Ordering::SeqCst) {
                break;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    // 停止网络服务
    network_service.stop();

    // 获取最终的 VK
    let vk_lock = state.vk.lock().unwrap();
    let vk_clone = crypto_utils::copy_ec_point(vk_lock.as_ref().unwrap())?;
    Ok(vk_clone)
}
