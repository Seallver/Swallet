use crate::common::params::{get_system_params, HASH_LEN};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcPoint};
use openssl::symm::{Cipher, Crypter, Mode};
use rand::Rng;

// H1: 哈希到 Z_q*
pub fn h1(input: &[u8]) -> Result<BigNum, openssl::error::ErrorStack> {
    let params = get_system_params();
    let hash = openssl::sha::sha256(input);

    // 转换为 BigNum
    let result = BigNum::from_slice(&hash)?;

    // 创建 q-1
    let mut q_minus_one = params.order.to_owned()?;
    q_minus_one.sub_word(1)?;

    // 取模运算
    let mut ctx = BigNumContext::new()?;
    let mut remainder = BigNum::new()?;
    remainder.nnmod(&result, &q_minus_one, &mut ctx)?;

    // 加 1 确保在 [1, q-1] 范围内
    remainder.add_word(1)?;

    Ok(remainder)
}

// H2: 简单的 SHA256
pub fn h2(input: &[u8]) -> Result<[u8; HASH_LEN], openssl::error::ErrorStack> {
    let hash = openssl::sha::sha256(input);
    Ok(hash)
}

// 生成 Z_q 中的随机数
pub fn random_in_zq() -> Result<BigNum, openssl::error::ErrorStack> {
    let sys_params = get_system_params();
    let mut rng = rand::rng();
    let bytes_needed = (sys_params.order.num_bits() as usize + 7) / 8;
    let mut buf = vec![0u8; bytes_needed];

    loop {
        rng.fill(&mut buf[..]);
        let candidate = BigNum::from_slice(&buf)?;

        if candidate < *sys_params.order {
            return Ok(candidate);
        }
    }
}

// 生成 Z_q* 中的随机数 (1 到 q-1)
pub fn random_in_zq_star() -> Result<BigNum, openssl::error::ErrorStack> {
    let mut rng = rand::rng();
    let sys_params = get_system_params();
    let bytes_needed = (sys_params.order.num_bits() as usize + 7) / 8;
    let mut buf = vec![0u8; bytes_needed];
    let zero = BigNum::from_u32(0)?;
    loop {
        rng.fill(&mut buf[..]);
        let candidate = BigNum::from_slice(&buf)?;

        // 取模 q
        let mut remainder = BigNum::new()?;
        let mut ctx = BigNumContext::new()?;
        remainder.nnmod(&candidate, &sys_params.order, &mut ctx)?;

        // 确保不为 0 (在 Z_q* 中)
        if remainder != zero {
            return Ok(remainder);
        }
    }
}

pub fn copy_ec_point(point: &EcPoint) -> Result<EcPoint, openssl::error::ErrorStack> {
    let params = get_system_params();
    let group = &params.group;
    let mut ctx = BigNumContext::new()?;

    // 转换为字节再转回
    let point_bytes = point.to_bytes(
        group,
        openssl::ec::PointConversionForm::COMPRESSED,
        &mut ctx,
    )?;

    EcPoint::from_bytes(group, &point_bytes, &mut ctx)
}

// 在椭圆曲线群中生成随机点
pub fn random_in_group() -> Result<EcPoint, openssl::error::ErrorStack> {
    let sys_params = get_system_params();
    let group = &sys_params.group;
    let mut ctx = BigNumContext::new()?;
    let a = random_in_zq_star()?;

    let mut result = EcPoint::new(&group)?;
    result.mul(&group, &sys_params.generator, &a, &mut ctx)?;

    Ok(result)
}

// H3: 把椭圆曲线群元素映射为 Z_q*
pub fn h3(point: &EcPoint) -> Result<BigNum, openssl::error::ErrorStack> {
    let params = get_system_params();
    let group = &params.group;
    let mut ctx = BigNumContext::new()?;

    // 获取点的压缩字节表示
    let point_bytes = point.to_bytes(
        group,
        openssl::ec::PointConversionForm::COMPRESSED,
        &mut ctx,
    )?;

    // 计算 SHA256
    let hash = openssl::sha::sha256(&point_bytes);

    // 转换为 BigNum
    let result = BigNum::from_slice(&hash)?;

    // 创建 q-1
    let mut q_minus_one = params.order.to_owned()?;
    q_minus_one.sub_word(1)?;

    let mut remainder = BigNum::new()?;
    remainder.nnmod(&result, &q_minus_one, &mut ctx)?;

    // 加 1 确保在 [1, q-1] 范围内
    remainder.add_word(1)?;

    Ok(remainder)
}

// 获取点的 x 坐标
pub fn get_point_x_coordinate(point: &EcPoint) -> Result<BigNum, openssl::error::ErrorStack> {
    let sys_params = get_system_params();
    let group = &sys_params.group;
    let mut ctx = BigNumContext::new()?;

    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;
    point.affine_coordinates(group, &mut x, &mut y, &mut ctx)?;

    Ok(x)
}

// AES-256-CBC 加密
pub fn encrypt(key: &[u8; 32], msg: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let mut iv = [0u8; 16];
    rand::rng().fill(&mut iv);

    let cipher = Cipher::aes_256_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(&iv))?;

    let mut ciphertext = vec![0u8; msg.len() + cipher.block_size()];
    let mut count = crypter.update(msg, &mut ciphertext)?;
    count += crypter.finalize(&mut ciphertext[count..])?;

    ciphertext.truncate(count);

    // 组合结果: IV + 密文
    let mut result = Vec::with_capacity(16 + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

// AES-256-CBC 解密
pub fn decrypt(key: &[u8; 32], packet: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    if packet.len() < 16 {
        return Err(openssl::error::ErrorStack::get());
    }

    let iv = &packet[0..16];
    let ciphertext = &packet[16..];

    let cipher = Cipher::aes_256_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))?;

    let mut plaintext = vec![0u8; ciphertext.len() + cipher.block_size()];
    let mut count = crypter.update(ciphertext, &mut plaintext)?;
    count += crypter.finalize(&mut plaintext[count..])?;

    plaintext.truncate(count);
    Ok(plaintext)
}

// 包装的加密函数，包含长度信息（仿照原C代码）
pub fn enc_with_length(key: &[u8; 32], msg: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let encrypted = encrypt(key, msg)?;
    let total_len = (encrypted.len() as u32).to_be_bytes();

    let mut result = Vec::with_capacity(4 + encrypted.len());
    result.extend_from_slice(&total_len);
    result.extend_from_slice(&encrypted);

    Ok(result)
}

// 包装的解密函数，解析长度信息
pub fn dec_with_length(
    key: &[u8; 32],
    packet: &[u8],
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    if packet.len() < 4 {
        return Err(openssl::error::ErrorStack::get());
    }

    let len_bytes = &packet[0..4];
    let expected_len =
        u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;

    if packet.len() < 4 + expected_len {
        return Err(openssl::error::ErrorStack::get());
    }

    decrypt(key, &packet[4..4 + expected_len])
}

// 辅助函数：检查 BigNum 是否为 Z_q* 中的元素
pub fn is_in_zq_star(num: &BigNum) -> bool {
    let sys_params = get_system_params();

    // 创建 0 并比较
    let zero = BigNum::from_u32(0).unwrap();
    &zero != num && num < &sys_params.order
}

// 打印 VK 坐标
pub fn print_point(point: &EcPoint) -> Result<(), openssl::error::ErrorStack> {
    let params = get_system_params();
    let group = &params.group;
    let mut ctx = BigNumContext::new()?;

    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;

    if point
        .affine_coordinates(group, &mut x, &mut y, &mut ctx)
        .is_ok()
    {
        println!("  x = {}", x.to_hex_str()?.to_string());
        println!("  y = {}", y.to_hex_str()?.to_string());
    }

    Ok(())
}

// 辅助函数：复制 Option<EcPoint>
pub fn copy_ec_point_option(
    opt: &Option<EcPoint>,
    group: &EcGroup,
) -> Result<Option<EcPoint>, Box<dyn std::error::Error>> {
    match opt.as_ref() {
        Some(point) => Ok(Some(point.to_owned().as_ref().to_owned(group)?)),
        None => Ok(None),
    }
}

// 辅助函数：复制 Option<BigNum>
pub fn copy_bn_option(opt: &Option<BigNum>) -> Result<Option<BigNum>, Box<dyn std::error::Error>> {
    match opt.as_ref() {
        Some(bn) => Ok(Some(bn.as_ref().to_owned()?)), // 使用之前的模式
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::bn::BigNum;
    use openssl::ec::EcGroup;
    use openssl::nid::Nid;

    #[test]
    fn test_h1() {
        let test_data = b"Test data for H1";
        let result = h1(test_data);

        assert!(result.is_ok());
        let h1_value = result.unwrap();

        // 验证结果在 [1, q-1] 范围内
        let params = get_system_params();
        let mut q_minus_one = params.order.to_owned().unwrap();
        q_minus_one.sub_word(1).unwrap();

        assert!(h1_value >= BigNum::from_u32(1).unwrap());
        assert!(h1_value <= q_minus_one);
    }

    #[test]
    fn test_h1_deterministic() {
        let test_data = b"Consistent input";
        let result1 = h1(test_data).unwrap();
        let result2 = h1(test_data).unwrap();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_h2() {
        let test_data = b"Test data for H2";
        let result = h2(test_data);

        assert!(result.is_ok());
        let hash = result.unwrap();

        // 验证哈希长度正确
        assert_eq!(hash.len(), HASH_LEN);

        // 验证不是全零
        assert_ne!(hash, [0u8; HASH_LEN]);
    }

    #[test]
    fn test_h2_deterministic() {
        let test_data = b"Same input, same output";
        let result1 = h2(test_data).unwrap();
        let result2 = h2(test_data).unwrap();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_random_in_zq() {
        for _ in 0..10 {
            // 多次测试确保随机性
            let result = random_in_zq();
            assert!(result.is_ok());

            let value = result.unwrap();
            let params = get_system_params();

            // 验证在 [0, q-1] 范围内
            assert!(value < params.order);
            assert!(value >= BigNum::from_u32(0).unwrap());
        }
    }

    #[test]
    fn test_random_in_zq_star() {
        for _ in 0..10 {
            let result = random_in_zq_star();
            assert!(result.is_ok());

            let value = result.unwrap();
            let params = get_system_params();

            // 验证在 [1, q-1] 范围内
            assert!(value < params.order);
            assert!(value > BigNum::from_u32(0).unwrap());

            // 验证 is_in_zq_star 函数
            assert!(is_in_zq_star(&value));
        }
    }

    #[test]
    fn test_is_in_zq_star() {
        let params = get_system_params();

        // 测试 0（应该为 false）
        let zero = BigNum::from_u32(0).unwrap();
        assert!(!is_in_zq_star(&zero));

        // 测试 1（应该为 true）
        let one = BigNum::from_u32(1).unwrap();
        assert!(one < params.order);
        assert!(is_in_zq_star(&one));

        // 测试 q-1（应该为 true）
        let mut q_minus_one = params.order.to_owned().unwrap();
        q_minus_one.sub_word(1).unwrap();
        assert!(is_in_zq_star(&q_minus_one));

        // 测试 q（应该为 false）
        assert!(!is_in_zq_star(&params.order));
    }

    #[test]
    fn test_copy_ec_point() {
        let group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();

        // 创建原始点
        let original = random_in_group().unwrap();

        // 测试复制
        let copied = copy_ec_point(&original).unwrap();

        // 验证两个点相等
        assert!(original.eq(&group, &copied, &mut ctx).unwrap_or(false));
    }

    #[test]
    fn test_random_in_group() {
        let group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();

        for _ in 0..5 {
            let result = random_in_group();
            assert!(result.is_ok());

            let point = result.unwrap();

            // 验证点在曲线上
            assert!(point.is_on_curve(&group, &mut ctx).unwrap_or(false));
        }
    }

    #[test]
    fn test_h3() {
        let point = random_in_group().unwrap();
        let result = h3(&point);

        assert!(result.is_ok());
        let h3_value = result.unwrap();

        // 验证结果在 [1, q-1] 范围内
        let params = get_system_params();
        let mut q_minus_one = params.order.to_owned().unwrap();
        q_minus_one.sub_word(1).unwrap();

        assert!(h3_value >= BigNum::from_u32(1).unwrap());
        assert!(h3_value <= q_minus_one);
    }

    #[test]
    fn test_h3_deterministic() {
        let point = random_in_group().unwrap();
        let result1 = h3(&point).unwrap();
        let result2 = h3(&point).unwrap();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_get_point_x_coordinate() {
        let point = random_in_group().unwrap();
        let result = get_point_x_coordinate(&point);

        assert!(result.is_ok());
        let x = result.unwrap();

        // x 坐标应该是一个有效的数
        assert!(x.num_bits() > 0);
    }

    #[test]
    fn test_encryption_decryption() {
        // 生成随机密钥 - 使用 thread_rng()
        let mut key = [0u8; 32];
        rand::rng().fill(&mut key);

        let test_messages = [
            &b""[..], // 确保是切片引用
            &b"a"[..],
            &b"hello world"[..],
            &b"This is a longer test message for encryption and decryption"[..],
        ];

        for message in test_messages.iter() {
            // 加密
            let encrypted = encrypt(&key, message);
            assert!(encrypted.is_ok());
            let ciphertext = encrypted.unwrap();

            // 解密
            let decrypted = decrypt(&key, &ciphertext);
            assert!(decrypted.is_ok());
            let plaintext = decrypted.unwrap();

            // 验证解密后的数据与原始数据一致
            assert_eq!(*message, plaintext.as_slice());
        }
    }

    #[test]
    fn test_enc_with_length_dec_with_length() {
        // 生成随机密钥
        let mut key = [0u8; 32];
        rand::rng().fill(&mut key);

        let test_message = b"Test message with length prefix for encryption";

        // 加密（带长度）
        let encrypted = enc_with_length(&key, test_message);
        assert!(encrypted.is_ok());
        let ciphertext_with_length = encrypted.unwrap();

        // 解密（带长度）
        let decrypted = dec_with_length(&key, &ciphertext_with_length);
        assert!(decrypted.is_ok());
        let plaintext = decrypted.unwrap();

        // 验证解密后的数据与原始数据一致
        assert_eq!(test_message, plaintext.as_slice());
    }

    #[test]
    fn test_dec_with_length_invalid_data() {
        let key = [0u8; 32];

        // 测试数据太短
        let short_data = [0u8; 3];
        let result = dec_with_length(&key, &short_data);
        assert!(result.is_err());

        // 测试长度字段与实际数据不匹配
        let mut invalid_data = vec![0u8; 20];
        // 设置长度为 100，但实际只有 20 字节
        invalid_data[0..4].copy_from_slice(&100u32.to_be_bytes());
        let result = dec_with_length(&key, &invalid_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_message_encryption() {
        let mut key = [0u8; 32];
        rand::rng().fill(&mut key);

        let empty_message = b"";
        let encrypted = encrypt(&key, empty_message).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(empty_message, decrypted.as_slice());
    }

    #[test]
    fn test_large_message_encryption() {
        let mut key = [0u8; 32];
        rand::rng().fill(&mut key);

        // 创建 1KB 的测试数据
        let large_message: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();

        let encrypted = encrypt(&key, &large_message).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(large_message, decrypted);
    }
}
