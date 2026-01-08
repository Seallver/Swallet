// party_keygen.rs
use crate::common::network::{
    broadcast, deserialize_ec_point, serialize_ec_point, MessageType, NetworkMessage,
    NetworkService,
};
use crate::common::params::get_system_params;
use crate::common::{self, crypto_utils};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::EcPoint;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
// 密钥对结构
pub struct KeyPair {
    pub secret_share: BigNum,  // 秘密份额 x_i
    pub public_share: EcPoint, // 公开份额 y_i = g^{x_i}
    pub vk: EcPoint,           // 聚合总公钥 vk
}

impl KeyPair {
    pub fn new() -> Result<Self, openssl::error::ErrorStack> {
        let sys_params = get_system_params();
        let group = &sys_params.group;
        Ok(KeyPair {
            secret_share: BigNum::new()?,
            public_share: EcPoint::new(group)?,
            vk: EcPoint::new(group)?,
        })
    }

    // 验证公钥是否在曲线上
    pub fn verify_public_share(&self) -> Result<bool, openssl::error::ErrorStack> {
        let params = get_system_params();
        let group = &params.group;
        let mut ctx = BigNumContext::new()?;

        self.public_share.is_on_curve(group, &mut ctx)
    }
}

// 全局状态
pub struct PartyKeygenState {
    pub key_pair: Arc<Mutex<Option<KeyPair>>>,
    pub vk_received_count: Arc<Mutex<usize>>,
}

impl PartyKeygenState {
    pub fn new() -> Self {
        PartyKeygenState {
            key_pair: Arc::new(Mutex::new(None)),
            vk_received_count: Arc::new(Mutex::new(0)),
        }
    }
}

// 生成密钥对
pub fn generate_key_pair() -> Result<KeyPair, Box<dyn std::error::Error>> {
    let params = get_system_params();
    let group = &params.group;
    let mut ctx = BigNumContext::new()?;

    // 创建密钥对结构
    let mut key_pair = KeyPair::new()?;

    // 随机生成私钥 (x_i ∈ Z_q*)
    key_pair.secret_share = crypto_utils::random_in_zq_star()?;

    // 计算公钥 y_i = g^{x_i}
    let generator = &params.generator;
    key_pair
        .public_share
        .mul(group, &generator, &key_pair.secret_share, &mut ctx)?;

    // 验证公钥是否合法（在曲线上）
    if !key_pair.verify_public_share()? {
        return Err("Generated public share is not on the curve".into());
    }

    key_pair.vk = key_pair.public_share.to_owned(group)?;

    println!("[+] Generated key pair successfully");

    Ok(key_pair)
}

// 消息处理器创建函数
pub fn create_keygen_handler(
    state: Arc<PartyKeygenState>,
) -> Box<dyn Fn(&NetworkMessage) + Send + Sync + 'static> {
    Box::new(move |msg: &NetworkMessage| {
        keygen_message_handler(msg, Arc::clone(&state));
    })
}

fn keygen_message_handler(msg: &NetworkMessage, state: Arc<PartyKeygenState>) {
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
    state: &PartyKeygenState,
) -> Result<bool, Box<dyn std::error::Error>> {
    let params = get_system_params();
    let group = &params.group;
    let mut ctx = BigNumContext::new()?;

    // 反序列化 VK_i
    let vk_i_hex = String::from_utf8_lossy(&msg.data)
        .trim_matches('\0')
        .to_string();
    let vk_i = deserialize_ec_point(&vk_i_hex)?;

    let mut count_lock = state.vk_received_count.lock().unwrap();
    let mut key_pair_lock = state.key_pair.lock().unwrap();

    // 累加到现有的 VK 上
    loop {
        if let Some(ref mut key_pair) = *key_pair_lock {
            // 计算 vk_new = vk_current + vk_i
            let mut vk_new = EcPoint::new(group)?;
            vk_new.add(group, &key_pair.vk, &vk_i, &mut ctx)?;
            key_pair.vk = vk_new;
            break;
        }
        // 短暂休眠避免忙等待
        std::thread::sleep(Duration::from_millis(10));
    }

    *count_lock += 1;

    // 检查是否收到所有参与方的 VK
    if *count_lock >= common::params::NUM_PARTIES - 1 {
        // 打印最终的聚合公钥
        if let Some(ref key_pair) = *key_pair_lock {
            let vk_hex = serialize_ec_point(&key_pair.vk)?;
            println!("[+] Final aggregated public key (VK): {}", vk_hex);
        }
        return Ok(true); // 应该停止监听
    }

    Ok(false) // 继续监听
}

// 广播本地的公钥分片
pub fn public_vk(key_pair: &KeyPair) -> Result<(), Box<dyn std::error::Error>> {
    // 序列化公钥
    let vk_hex = serialize_ec_point(&key_pair.public_share)?;

    // 广播公钥分片
    broadcast(MessageType::MsgPublicVk, vk_hex.as_bytes())?;

    println!("[+] Broadcasted public VK share to all parties");

    Ok(())
}

pub fn run_keygen(
    key_pair: KeyPair,
    listen_port: u16,
    party_id: usize,
) -> Result<KeyPair, Box<dyn std::error::Error>> {
    // 创建状态
    let state = Arc::new(PartyKeygenState::new());
    {
        let mut key_pair_lock = state.key_pair.lock().unwrap();
        *key_pair_lock = Some(key_pair);
    }

    // 创建网络服务
    let mut network_service = NetworkService::new();

    // 设置消息处理器
    let handler = create_keygen_handler(Arc::clone(&state));
    network_service.set_message_handler(handler);

    // 启动监听线程
    network_service.start_listen_thread(listen_port)?;

    println!(
        "[*] Party {} started, listening on port {}",
        party_id, listen_port
    );

    //同步参与方监听操作
    thread::sleep(Duration::from_millis(2000));

    // 广播公钥分片
    {
        let key_pair_lock = state.key_pair.lock().unwrap();
        if let Some(ref key_pair) = *key_pair_lock {
            public_vk(key_pair)?;
        }
    }

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

    // 获取最终的密钥对
    let mut key_pair_lock = state.key_pair.lock().unwrap();
    key_pair_lock.take().ok_or("Failed to get key pair".into())
}

// 测试模块
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_pair() {
        // 测试密钥对生成
        let result = generate_key_pair();
        assert!(result.is_ok());

        let key_pair = result.unwrap();

        // 验证私钥不为零
        assert!(key_pair.secret_share.num_bits() > 0);

        // 验证公钥在曲线上
        assert!(key_pair.verify_public_share().unwrap_or(false));
    }

    #[test]
    fn test_keypair_new() {
        let key_pair = KeyPair::new();
        assert!(key_pair.is_ok());
    }
}
