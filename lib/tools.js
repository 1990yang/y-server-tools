
const Basen = require('basen');
const crypto = require('crypto');
const fs = require('fs');

var middleware = module.exports = () => {}

/**
 * 获取uuid
 * eg. 7AB99A23-C2A6-4B84-AE73-89897195200C
 * @return {string}
 */
middleware.getUUID = () => {
    var chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split('');
    var uuid = [], i;
    // rfc4122, version 4 form
    var r;

    // rfc4122 requires these characters
    uuid[8] = uuid[13] = uuid[18] = uuid[23] = '-';
    uuid[14] = '4';

    // Fill in random data. At i==19 set the high bits of clock sequence as
    // per rfc4122, sec. 4.1.5
    for (i = 0; i < 36; i++) {
        if (!uuid[i]) {
            r = 0 | Math.random() * 16;
            uuid[i] = chars[(i === 19) ? (r & 0x3) | 0x8 : r];
        }
    }

    return uuid.join('');
}

middleware.randomWithCount = (count) => {
  var result = '';
  var possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (var i = 0; i < count; i++) {
      result += possible.charAt(Math.floor(Math.random() * possible.length));
  }

  return result;
}

middleware.generateAppkey = () => {
  var rand62 = middleware.randomWithCount(4);
  var time = new Date().getTime();
  var time62 = new Basen().encode(time);
  return rand62 + time62;
}

middleware.generateAppSecret = (appkey) => {
  var time = new Date().getTime();
  var timeStr62 = new Basen().encode(time);
  var tmp = appkey + timeStr62 + 'yodo1scrt43443' + Math.floor(Math.random() * 9999).toString();
  return crypto.createHash('md5').update(tmp).digest('hex');
}

const secretkey = 'xxxyodo1xxx'; // 唯一（公共）秘钥
middleware.cryptedAES = (content) => {
  var cipher = crypto.createCipher('aes192', secretkey); // 使用aes192加密
  var enc = cipher.update(content, 'utf8', 'hex');
  enc += cipher.final('hex');
  return enc;
}

middleware.decryptedAES = (cryptedContent) => {
  var decipher = crypto.createDecipher('aes192', secretkey);
  var dec = decipher.update(cryptedContent, 'hex', 'utf8');
  dec += decipher.final('utf8');
  return dec;
}

middleware.isJson = (para) => {
  if (typeof para === 'string') {
    try {
      var obj = JSON.parse(para);
      return typeof obj === 'object' && obj;
    } catch (e) {
      return false;
    }
  } else if (typeof para === 'object') {
    return (Object.prototype.toString.call(para).toLowerCase() === '[object object]' && !para.length) || (Object.prototype.toString.call(para).toLowerCase() === '[object array]' && para.length);
  }
  return false;
}

middleware.isArray = (para) => {
  return Object.prototype.toString.call(para).toLowerCase() === '[object array]';
}

middleware.isObj = (para) => {
  return Object.prototype.toString.call(para).toLowerCase() === '[object object]';
}

middleware.isStr = (para) => {
  return typeof para === 'string';
}

middleware.isStrNull = (str) => {
  return (!str || typeof str === 'undefined' || str.length === 0);
}

middleware.processSpace = (str) => {
  return str.replace(/(^\s*)|(\s*$)/g, '');
}

/**
 * 对比两个值的类型，以a的类型为主
 * ps:目前只支持string和object的特殊处理
 * @param a
 * @param b
 * @returns {boolean}
 */
middleware.compareA = (a, b) => {
  if (typeof a === 'string') {
    return (typeof b === 'string')
  } else if (typeof a === 'object') {
    return Object.prototype.toString.call(a).toLowerCase() === Object.prototype.toString.call(b).toLowerCase()
  } else {
    return (typeof a === typeof b);
  }
}

/**
 * 获取文件内容
 * @param file 文件路径
 */
middleware.readFileData = (file) => {
  return fs.readFileSync(file, 'utf-8');
}
