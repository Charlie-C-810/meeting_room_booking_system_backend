import * as crypto from 'crypto';

/**
 * 计算给定字符串的MD5哈希值。
 *
 * 使用Node.js的crypto模块来计算输入字符串的MD5哈希值。此函数对传入的字符串进行哈希处理，
 * 适用于需要对数据进行加密或验证数据完整性的场景。
 *
 * @param str 待计算MD5哈希值的字符串
 * @returns 返回计算得到的MD5哈希值字符串
 */
export function md5(str) {
  // 创建一个MD5哈希算法实例
  const hash = crypto.createHash('md5');
  // 更新哈希实例的输入数据为传入的字符串
  hash.update(str);
  // 获取并返回哈希值，以十六进制字符串形式表示
  return hash.digest('hex');
}
