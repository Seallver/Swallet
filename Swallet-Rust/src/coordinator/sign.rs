// sign.rs
use crate::common::crypto_utils::{
    copy_bn_option, copy_ec_point, decrypt, encrypt, get_point_x_coordinate, h1, h3,
    random_in_group, random_in_zq_star,
};

use crate::common::network::{
    deserialize_ec_point, send_message, serialize_ec_point, MessageType, NetworkMessage,
    NetworkService,
};
use crate::common::params::{get_system_params, MESSAGE, NUM_PARTIES, PASSWORD_PRIME};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcPoint};
use openssl::hash::{Hasher, MessageDigest};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::Duration;

// 全局状态
static RECEIVED: AtomicI32 = AtomicI32::new(0);
static OFFLINE_ID: AtomicI32 = AtomicI32::new(-1);
static ONLINE_COUNT: AtomicI32 = AtomicI32::new(NUM_PARTIES as i32);

// Coordinator 结构体
pub struct Coordinator {
    // 公开参数
    pub a: Option<EcPoint>,
    pub b: Option<EcPoint>,

    // 从参与方接收的数据
    pub delta_i: Vec<Option<EcPoint>>,
    pub rw_i_prime: Vec<Option<EcPoint>>,
    pub mu_i: Vec<Option<BigNum>>,
    pub l_i: Vec<Option<EcPoint>>,
    pub m_i: Vec<Option<EcPoint>>,
    pub n_i_prime: Vec<Option<EcPoint>>,
    pub key_i_prime: Vec<Option<[u8; 32]>>,

    // 签名分片
    pub w_i: Vec<Option<BigNum>>,
    pub u_i: Vec<Option<BigNum>>,

    // 最终签名
    pub s: Option<BigNum>,
    pub r: Option<BigNum>,
}

impl Coordinator {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let party_count = NUM_PARTIES + 1;

        let mut delta_i = Vec::with_capacity(party_count);
        let mut rw_i_prime = Vec::with_capacity(party_count);
        let mut mu_i = Vec::with_capacity(party_count);
        let mut l_i = Vec::with_capacity(party_count);
        let mut m_i = Vec::with_capacity(party_count);
        let mut n_i_prime = Vec::with_capacity(party_count);
        let mut key_i_prime = Vec::with_capacity(party_count);
        let mut w_i = Vec::with_capacity(party_count);
        let mut u_i = Vec::with_capacity(party_count);

        for _ in 0..party_count {
            delta_i.push(None);
            rw_i_prime.push(None);
            mu_i.push(None);
            l_i.push(None);
            m_i.push(None);
            n_i_prime.push(None);
            key_i_prime.push(None);
            w_i.push(None);
            u_i.push(None);
        }

        Ok(Coordinator {
            a: None,
            b: None,
            delta_i,
            rw_i_prime,
            mu_i,
            l_i,
            m_i,
            n_i_prime,
            key_i_prime,
            w_i,
            u_i,
            s: None,
            r: None,
        })
    }
}

// 全局 coordinator 实例
pub static COORD: LazyLock<Mutex<Coordinator>> =
    LazyLock::new(|| Mutex::new(Coordinator::new().expect("Failed to create Coordinator")));

// 消息处理器
pub fn create_sign_handler() -> Box<dyn Fn(&NetworkMessage) + Send + Sync + 'static> {
    Box::new(move |msg: &NetworkMessage| {
        sign_message_handler(msg);
    })
}

fn sign_message_handler(msg: &NetworkMessage) {
    if msg.msg_type == MessageType::MsgP2CDelta {
        match handle_delta_msg(msg) {
            Ok(_) => {
                RECEIVED.fetch_add(1, Ordering::SeqCst);
            }
            Err(e) => {
                eprintln!("Error handling Delta message: {:?}", e);
            }
        }
    } else if msg.msg_type == MessageType::MsgP2CM {
        match handle_m_msg(msg) {
            Ok(_) => {
                RECEIVED.fetch_add(1, Ordering::SeqCst);
            }
            Err(e) => {
                eprintln!("Error handling M message: {:?}", e);
            }
        }
    } else if msg.msg_type == MessageType::MsgP2CSigma {
        match handle_sigma_msg(msg) {
            Ok(_) => {
                RECEIVED.fetch_add(1, Ordering::SeqCst);
            }
            Err(e) => {
                eprintln!("Error handling Sigma message: {:?}", e);
            }
        }
    } else {
        println!(
            "Received unexpected message type in sign phase: {}",
            msg.msg_type.as_str()
        );
    }
}

fn handle_delta_msg(msg: &NetworkMessage) -> Result<(), Box<dyn std::error::Error>> {
    let party_id = msg.src_id as usize;

    if party_id <= 0 || party_id > NUM_PARTIES {
        return Err(format!("Invalid participant ID: {}", party_id).into());
    }

    let delta_hex = String::from_utf8_lossy(&msg.data)
        .trim_matches('\0')
        .to_string();

    let delta = deserialize_ec_point(&delta_hex)?;

    let mut coord_lock = COORD.lock().unwrap();
    coord_lock.delta_i[party_id] = Some(delta);

    Ok(())
}

fn handle_m_msg(msg: &NetworkMessage) -> Result<(), Box<dyn std::error::Error>> {
    let party_id = msg.src_id as usize;

    if party_id <= 0 || party_id > NUM_PARTIES {
        return Err(format!("Invalid participant ID: {}", party_id).into());
    }

    let m_hex = String::from_utf8_lossy(&msg.data)
        .trim_matches('\0')
        .to_string();

    let m = deserialize_ec_point(&m_hex)?;

    let mut coord_lock = COORD.lock().unwrap();
    coord_lock.m_i[party_id] = Some(m);

    Ok(())
}

fn handle_sigma_msg(msg: &NetworkMessage) -> Result<(), Box<dyn std::error::Error>> {
    let party_id = msg.src_id as usize;

    if party_id <= 0 || party_id > NUM_PARTIES {
        return Err(format!("Invalid participant ID: {}", party_id).into());
    }

    let data = &msg.data;

    // 第一步：解析密文长度
    if data.len() < 4 {
        return Err("Data too short for ciphertext length".into());
    }

    let ct_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;

    // 提取密文部分
    let ciphertext = &data[4..4 + ct_len];

    // 获取密钥
    let key = {
        let coord_lock = COORD.lock().unwrap();
        coord_lock.key_i_prime[party_id]
            .as_ref()
            .ok_or("Key not available")?
            .clone()
    };

    // 解密
    let plaintext = decrypt(&key, ciphertext)?;

    // 解析数据: w_len(4字节) + w + u_len(4字节) + u
    if plaintext.len() < 8 {
        return Err("Plaintext too short".into());
    }

    let mut pos = 0;

    // 解析 w_len
    let w_len = u32::from_be_bytes([
        plaintext[pos],
        plaintext[pos + 1],
        plaintext[pos + 2],
        plaintext[pos + 3],
    ]) as usize;
    pos += 4;

    if pos + w_len > plaintext.len() {
        return Err("Invalid w_len".into());
    }

    // 解析 w
    let w = BigNum::from_slice(&plaintext[pos..pos + w_len])?;
    pos += w_len;

    // 解析 u_len
    if plaintext.len() - pos < 4 {
        return Err("Missing u_len".into());
    }

    let u_len = u32::from_be_bytes([
        plaintext[pos],
        plaintext[pos + 1],
        plaintext[pos + 2],
        plaintext[pos + 3],
    ]) as usize;
    pos += 4;

    if pos + u_len > plaintext.len() {
        return Err("Invalid u_len".into());
    }

    // 解析 u
    let u = BigNum::from_slice(&plaintext[pos..pos + u_len])?;

    // 存储到 coordinator
    let mut coord_lock = COORD.lock().unwrap();
    coord_lock.w_i[party_id] = Some(w);
    coord_lock.u_i[party_id] = Some(u);

    Ok(())
}

pub fn step1() -> Result<(), Box<dyn std::error::Error>> {
    let params = get_system_params();

    // 随机生成 a, b
    let a = random_in_group()?;
    let b = random_in_group()?;

    // 更新 coordinator
    {
        let mut coord_lock = COORD.lock().unwrap();
        coord_lock.a = Some(copy_ec_point(&a)?);
        coord_lock.b = Some(copy_ec_point(&b)?);
    }

    // 序列化 a 和 b
    let a_hex = serialize_ec_point(&a)?;
    let b_hex = serialize_ec_point(&b)?;
    let a_hex = a_hex.trim_matches('\0');
    let b_hex = b_hex.trim_matches('\0');

    // 拼接数据
    let data = format!("{}{}", a_hex, b_hex);

    // 发送给所有参与方
    for i in 1..=NUM_PARTIES {
        if i == OFFLINE_ID.load(Ordering::SeqCst) as usize {
            continue;
        }

        let party = &params.parties[i];

        match send_message(
            0,
            &party.ip,
            party.port as u16,
            MessageType::RequestSign,
            data.as_bytes(),
        ) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Failed to send to party {}: {:?}", i, e);

                let current_offline = OFFLINE_ID.load(Ordering::SeqCst);
                if current_offline == -1 {
                    OFFLINE_ID.store(i as i32, Ordering::SeqCst);
                    ONLINE_COUNT.fetch_sub(1, Ordering::SeqCst);
                    println!("[*] Party {} marked as offline", i);
                } else {
                    return Err("Too many parties are offline".into());
                }
            }
        }
    }

    Ok(())
}

pub fn broadcast_offline() -> Result<(), Box<dyn std::error::Error>> {
    let offline_id = OFFLINE_ID.load(Ordering::SeqCst);

    let offline_str = offline_id.to_string();
    let params = get_system_params();

    for id in 1..=NUM_PARTIES {
        if id == offline_id as usize {
            continue;
        }

        let party = &params.parties[id];

        send_message(
            0,
            &party.ip,
            party.port as u16,
            MessageType::SignalOffline,
            offline_str.as_bytes(),
        )?;
    }

    Ok(())
}

pub fn step3() -> Result<(), Box<dyn std::error::Error>> {
    let params = get_system_params();
    let group = &params.group;
    let mut ctx = BigNumContext::new()?;
    let offline_id = OFFLINE_ID.load(Ordering::SeqCst) as usize;

    // 计算 h'
    let h_prime = h1(PASSWORD_PRIME.as_bytes())?;

    for i in 1..=NUM_PARTIES {
        if i == offline_id {
            continue;
        }

        // 获取 Delta_i
        let delta = {
            let coord_lock = COORD.lock().unwrap();
            copy_ec_point(
                coord_lock.delta_i[i]
                    .as_ref()
                    .ok_or("Delta_i not available")?,
            )?
        };

        // 随机生成 mu
        let mu = random_in_zq_star()?;

        // 计算 rw_i' = delta_i^{h'}
        let mut rw_prime = EcPoint::new(group)?;
        rw_prime.mul(group, &delta, &h_prime, &mut ctx)?;

        // 计算 rw_hash = H3(rw_i')
        let rw_hash = h3(&rw_prime)?;

        // 计算 L_i = g^{mu_i} * a^{rw_hash}
        let mut l_i = EcPoint::new(group)?;
        let mut temp1 = EcPoint::new(group)?;
        let mut temp2 = EcPoint::new(group)?;

        // temp1 = g^{mu_i}
        temp1.mul(group, &params.generator, &mu, &mut ctx)?;

        // temp2 = a^{rw_hash}
        let a_ref = {
            let coord_lock = COORD.lock().unwrap();
            copy_ec_point(coord_lock.a.as_ref().ok_or("a not available")?)?
        };
        temp2.mul(group, &a_ref, &rw_hash, &mut ctx)?;

        // L_i = temp1 + temp2
        l_i.add(group, &temp1, &temp2, &mut ctx)?;

        // 序列化 L_i 并发送
        let l_hex = serialize_ec_point(&l_i)?;
        let l_hex = l_hex.trim_matches('\0');

        // 存储到 coordinator
        {
            let mut coord_lock = COORD.lock().unwrap();
            coord_lock.mu_i[i] = Some(mu);
            coord_lock.rw_i_prime[i] = Some(rw_prime);
            coord_lock.l_i[i] = Some(l_i);
        }

        let party = &params.parties[i];
        send_message(
            0,
            &party.ip,
            party.port as u16,
            MessageType::MsgC2PL,
            l_hex.as_bytes(),
        )?;
    }

    Ok(())
}

pub fn step5() -> Result<(), Box<dyn std::error::Error>> {
    let params = get_system_params();
    let group = &params.group;
    let mut ctx = BigNumContext::new()?;
    let offline_id = OFFLINE_ID.load(Ordering::SeqCst) as usize;

    for id in 1..=NUM_PARTIES {
        if id == offline_id {
            continue;
        }

        // 获取需要的值
        let (rw_prime_ref, mu_opt, m_ref) = {
            let coord_lock = COORD.lock().unwrap();
            (
                copy_ec_point(
                    coord_lock.rw_i_prime[id]
                        .as_ref()
                        .ok_or("rw_i_prime not available")?,
                )?,
                copy_bn_option(&coord_lock.mu_i[id])?,
                copy_ec_point(coord_lock.m_i[id].as_ref().ok_or("M_i not available")?)?,
            )
        };

        let mu_ref = mu_opt.ok_or("mu_i not available")?;

        // 计算 rw_hash = H3(rw_i')
        let rw_hash = h3(&rw_prime_ref)?;

        // 计算 b^rw_hash
        let b_ref = {
            let coord_lock = COORD.lock().unwrap();
            copy_ec_point(coord_lock.b.as_ref().ok_or("b not available")?)?
        };

        let mut b_rw = EcPoint::new(group)?;
        b_rw.mul(group, &b_ref, &rw_hash, &mut ctx)?;

        // 计算 b^rw_hash 的逆
        b_rw.invert(group, &mut ctx)?;

        // 计算 temp = M_i * (b^rw_hash)^{-1}
        let mut temp = EcPoint::new(group)?;
        temp.add(group, &m_ref, &b_rw, &mut ctx)?;

        // 计算 N_i' = temp^{mu_i}
        let mut n_prime = EcPoint::new(group)?;
        n_prime.mul(group, &temp, &mu_ref, &mut ctx)?;

        // 计算密钥 key_i' = H2(rw_i' || id_C || id_P || L_i || M_i || N_i')
        let mut hasher = Hasher::new(MessageDigest::sha256())?;

        // 序列化 rw_i'
        let rw_bytes = serialize_ec_point(&rw_prime_ref)?;
        hasher.update(&rw_bytes.as_bytes()[..66])?;

        // id_C (coordinator identifier) = 0
        hasher.update(&[0])?;

        // id_P (party identifier)
        hasher.update(&[id as u8])?;

        // 序列化 L_i
        let l_ref = {
            let coord_lock = COORD.lock().unwrap();
            copy_ec_point(coord_lock.l_i[id].as_ref().ok_or("L_i not available")?)?
        };
        let l_bytes = serialize_ec_point(&l_ref)?;
        hasher.update(&l_bytes.as_bytes()[..66])?;

        // 序列化 M_i
        let m_bytes = serialize_ec_point(&m_ref)?;
        hasher.update(&m_bytes.as_bytes()[..66])?;

        // 序列化 N_i'
        let n_bytes = serialize_ec_point(&n_prime)?;
        hasher.update(&n_bytes.as_bytes()[..66])?;

        let hash_result = hasher.finish()?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_result);

        // 存储到 coordinator
        {
            let mut coord_lock = COORD.lock().unwrap();
            coord_lock.n_i_prime[id] = Some(n_prime);
            coord_lock.key_i_prime[id] = Some(key);
        }
    }

    Ok(())
}

pub fn step6() -> Result<(), Box<dyn std::error::Error>> {
    let params = get_system_params();
    let offline_id = OFFLINE_ID.load(Ordering::SeqCst) as usize;
    let message = MESSAGE.as_bytes();

    for id in 1..=NUM_PARTIES {
        if id == offline_id {
            continue;
        }

        // 获取密钥
        let key = {
            let coord_lock = COORD.lock().unwrap();
            coord_lock.key_i_prime[id]
                .as_ref()
                .ok_or("Key not available")?
                .clone()
        };

        // 加密消息
        let ciphertext = encrypt(&key, message)?;

        // 添加长度前缀
        let ct_len = ciphertext.len() as u32;
        let mut send_buf = Vec::with_capacity(4 + ciphertext.len());
        send_buf.extend_from_slice(&ct_len.to_be_bytes());
        send_buf.extend_from_slice(&ciphertext);

        // 发送密文
        let party = &params.parties[id];
        send_message(
            0,
            &party.ip,
            party.port as u16,
            MessageType::MsgC2PCt,
            &send_buf,
        )?;
    }

    Ok(())
}

pub fn step8(r_point: &EcPoint) -> Result<(), Box<dyn std::error::Error>> {
    let params = get_system_params();
    let q = &params.order;
    let offline_id = OFFLINE_ID.load(Ordering::SeqCst) as usize;

    // 计算 sum_u 和 sum_w
    let mut sum_u = BigNum::new()?;
    let mut sum_w = BigNum::new()?;
    let mut ctx = BigNumContext::new()?;

    for id in 1..=NUM_PARTIES {
        if id == offline_id {
            continue;
        }

        let (u_opt, w_opt) = {
            let coord_lock = COORD.lock().unwrap();
            (
                copy_bn_option(&coord_lock.u_i[id])?,
                copy_bn_option(&coord_lock.w_i[id])?,
            )
        };

        let u_ref = u_opt.ok_or("u_i not available")?;
        let w_ref = w_opt.ok_or("w_i not available")?;

        let temp_u = sum_u.to_owned()?;
        let temp_w = sum_w.to_owned()?;

        sum_u.mod_add(&temp_u, &u_ref, q, &mut ctx)?;
        sum_w.mod_add(&temp_w, &w_ref, q, &mut ctx)?;
    }

    // 计算 sum_u 的模逆
    let mut sum_u_inv = BigNum::new()?; // 创建新变量存储结果
    sum_u_inv.mod_inverse(&sum_u, &q, &mut ctx)?;

    // 计算 s = sum_w * sum_u_inv mod q
    let mut s = BigNum::new()?;
    s.mod_mul(&sum_w, &sum_u_inv, &q, &mut ctx)?;

    // 计算 r
    let r = get_point_x_coordinate(r_point)?;

    // 存储最终签名
    {
        let mut coord_lock = COORD.lock().unwrap();
        coord_lock.s = Some(s);
        coord_lock.r = Some(r);
        println!(
            "[+] Signature generated: r={},\n\t\t\t s={}",
            coord_lock.r.as_ref().unwrap().to_dec_str()?,
            coord_lock.s.as_ref().unwrap().to_dec_str()?
        );
    }

    Ok(())
}

pub fn verify_signature(
    r: &BigNum,
    s: &BigNum,
    vk: &EcPoint,
) -> Result<bool, Box<dyn std::error::Error>> {
    let params = get_system_params();
    let group: &EcGroup = &params.group;
    let n = &params.order;
    let mut ctx = BigNumContext::new()?;

    // 检查 r 和 s 的范围 [1, n-1]
    if r.eq(&BigNum::from_u32(0).unwrap()) || r >= n {
        println!("Invalid r value (out of range)");
        return Ok(false);
    }

    if s.eq(&BigNum::from_u32(0).unwrap()) || s >= n {
        println!("Invalid s value (out of range)");
        return Ok(false);
    }

    // 计算消息哈希 e = H(MESSAGE)
    let mut hasher = Hasher::new(MessageDigest::sha256())?;
    hasher.update(MESSAGE.as_bytes())?;
    let hash = hasher.finish()?;

    let mut e = BigNum::from_slice(&hash)?;

    let e_ref = e.to_owned()?;

    // 如果 e >= n，取模
    if &e >= n {
        e.mod_add(&e_ref, &BigNum::from_u32(0).unwrap(), n, &mut ctx)?;
    }

    // 计算 s 的模逆
    let mut s_inv = BigNum::new()?;
    s_inv.mod_inverse(s, n, &mut ctx)?;

    // 计算 u1 = e * s_inv mod n
    let mut u1 = BigNum::new()?;
    u1.mod_mul(&e, &s_inv, n, &mut ctx)?;

    // 计算 u2 = r * s_inv mod n
    let mut u2 = BigNum::new()?;
    u2.mod_mul(r, &s_inv, n, &mut ctx)?;

    // 计算点 P = u1 * G + u2 * vk
    let mut p1 = EcPoint::new(group)?;
    let mut p2 = EcPoint::new(group)?;
    let mut p = EcPoint::new(group)?;

    p1.mul(group, &params.generator, &u1, &mut ctx)?;
    p2.mul(group, vk, &u2, &mut ctx)?;
    p.add(group, &p1, &p2, &mut ctx)?;

    // 获取点 P 的 x 坐标
    let x_p = get_point_x_coordinate(&p)?;

    // 计算 x_p mod n
    let mut x_mod_n = BigNum::new()?;
    x_mod_n.mod_add(&x_p, &BigNum::from_u32(0).unwrap(), n, &mut ctx)?;

    // 验证 x_mod_n 是否等于 r
    let result = &x_mod_n == r;

    if result {
        println!("[+] Signature verification SUCCESS");
    } else {
        println!("[-] Signature verification FAILED");
        println!("  Computed x mod n: {}", x_mod_n.to_dec_str()?);
        println!("  Expected r:       {}", r.to_dec_str()?);
    }

    Ok(result)
}

pub fn run_sign(
    r_point: &EcPoint,
    vk: &EcPoint,
    listen_port: u16,
    party_id: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    // 创建网络服务
    let mut network_service = NetworkService::new();

    // 设置消息处理器
    let handler = create_sign_handler();
    network_service.set_message_handler(handler);

    // 重置退出标志
    crate::common::network::LISTEN_THREAD_EXIT.store(false, Ordering::SeqCst);

    // 启动监听线程
    network_service.start_listen_thread(listen_port)?;

    println!(
        "[*] Party {} started presign phase, listening on port {}",
        party_id, listen_port
    );

    match step1() {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error in Step 1: {:?}", e);
            return Err(e);
        }
    };

    match broadcast_offline() {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error broadcasting offline party: {:?}", e);
            return Err(e);
        }
    };

    loop {
        let received = RECEIVED.load(Ordering::SeqCst);
        let online_count = ONLINE_COUNT.load(Ordering::SeqCst);

        if received >= online_count {
            RECEIVED.store(0, Ordering::SeqCst);
            break;
        }

        thread::sleep(Duration::from_millis(100));
    }

    match step3() {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error in Step 3: {:?}", e);
            return Err(e);
        }
    };

    loop {
        let received = RECEIVED.load(Ordering::SeqCst);
        let online_count = ONLINE_COUNT.load(Ordering::SeqCst);

        if received >= online_count {
            RECEIVED.store(0, Ordering::SeqCst);
            break;
        }

        thread::sleep(Duration::from_millis(100));
    }

    match step5() {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error in Step 5: {:?}", e);
            return Err(e);
        }
    };

    match step6() {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error in Step 6: {:?}", e);
            return Err(e);
        }
    };

    loop {
        let received = RECEIVED.load(Ordering::SeqCst);
        let online_count = ONLINE_COUNT.load(Ordering::SeqCst);

        if received >= online_count {
            RECEIVED.store(0, Ordering::SeqCst);
            break;
        }

        thread::sleep(Duration::from_millis(100));
    }

    match step8(r_point) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error in Step 8: {:?}", e);
            return Err(e);
        }
    };

    let coord_lock = COORD.lock().unwrap();
    let r = coord_lock.r.as_ref().ok_or("r not available")?;
    let s = coord_lock.s.as_ref().ok_or("s not available")?;

    match verify_signature(r, s, vk) {
        Ok(true) => println!("[+] Signature verification SUCCESS"),
        Ok(false) => println!("[-] Signature verification FAILED"),
        Err(e) => eprintln!("Error during signature verification: {:?}", e),
    }

    // 停止网络服务
    network_service.stop();

    Ok(())
}
