package com.rymcu.forest.util;

import com.google.common.net.InetAddresses;
import com.google.common.net.InternetDomainName;
import lombok.extern.slf4j.Slf4j;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Created on 2023/12/29 11:52.
 *
 * @author ronger
 * @email ronger-x@outlook.com
 * @desc : com.rymcu.forest.util
 */
@Slf4j
public class SSRFUtil {

    /**
     * 允许的图片域名白名单
     */
    private static final Set<String> ALLOWED_IMAGE_DOMAINS = new HashSet<>(Arrays.asList(
            "rymcu.com",
            "github.com",
            "githubusercontent.com",
            "gitee.com",
            "coding.net"
    ));

    public static boolean checkUrl(URL url, boolean checkWhiteList) {
        // 协议限制 - 只允许 http 和 https
        String protocol = url.getProtocol().toLowerCase();
        if (!"http".equals(protocol) && !"https".equals(protocol)) {
            return false;
        }
        try {
            // 获取域名，并转为小写
            String host = url.getHost().toLowerCase();
            
            // 禁止访问本地主机名
            if ("localhost".equals(host) || host.endsWith(".local") || host.endsWith(".internal")) {
                return false;
            }
            
            // 判断是不是 IPv4 或 IPv6
            if (InetAddresses.isInetAddress(host)) {
                // 禁止内网 IP
                return !internalIp(host);
            }
            
            // 对域名进行 DNS 解析，检查解析后的 IP 是否为内网 IP（防止 DNS 重绑定攻击）
            if (!checkResolvedIp(host)) {
                return false;
            }
            
            if (checkWhiteList) {
                // 获取一级域名
                String rootDomain = InternetDomainName.from(host).topPrivateDomain().toString();
                // 检查是否在白名单中
                if (!ALLOWED_IMAGE_DOMAINS.contains(rootDomain)) {
                    log.warn("域名 {} 不在白名单中", rootDomain);
                    return false;
                }
            }
        } catch (IllegalArgumentException exception) {
            log.warn("URL 校验失败: {}", exception.getMessage());
            return false;
        }
        return true;
    }

    /**
     * 检查域名解析后的 IP 是否安全（非内网 IP）
     * 防止 DNS 重绑定攻击
     *
     * @param host 域名
     * @return true 表示安全，false 表示不安全
     */
    private static boolean checkResolvedIp(String host) {
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                String ip = address.getHostAddress();
                if (internalIp(ip)) {
                    log.warn("域名 {} 解析到内网 IP: {}", host, ip);
                    return false;
                }
            }
            return true;
        } catch (UnknownHostException e) {
            log.warn("无法解析域名: {}", host);
            return false;
        }
    }

    public static void main(String[] args) throws MalformedURLException {
        URL url = new URL("https://rymcu.com");
        boolean b = checkUrl(url, false);
        log.info(String.valueOf(b));
    }

    public static boolean internalIp(String ip) {
        // 检查 IPv6 环回地址
        if ("::1".equals(ip) || "0:0:0:0:0:0:0:1".equals(ip)) {
            return true;
        }
        // 检查 IPv6 本地地址
        if (ip.startsWith("fe80:") || ip.startsWith("fc00:") || ip.startsWith("fd00:")) {
            return true;
        }
        byte[] addr = textToNumericFormatV4(ip);
        return internalIp(addr) || "127.0.0.1".equals(ip) || "0.0.0.0".equals(ip);
    }

    private static boolean internalIp(byte[] addr) {
        if (Objects.isNull(addr) || addr.length < 2) {
            return false;
        }
        final byte b0 = addr[0];
        final byte b1 = addr[1];
        
        // 127.x.x.x/8 - 环回地址
        if (b0 == 127) {
            return true;
        }
        
        // 0.x.x.x/8 - 本网络
        if (b0 == 0) {
            return true;
        }
        
        // 10.x.x.x/8 - A 类私有地址
        final byte SECTION_1 = 0x0A;
        // 172.16.x.x/12 - B 类私有地址
        final byte SECTION_2 = (byte) 0xAC;
        final byte SECTION_3 = (byte) 0x10;
        final byte SECTION_4 = (byte) 0x1F;
        // 192.168.x.x/16 - C 类私有地址
        final byte SECTION_5 = (byte) 0xC0;
        final byte SECTION_6 = (byte) 0xA8;
        // 169.254.x.x/16 - 链路本地地址
        final byte SECTION_7 = (byte) 0xA9;
        final byte SECTION_8 = (byte) 0xFE;
        // 100.64.x.x/10 - 运营商级 NAT（云元数据服务常用）
        final byte SECTION_9 = (byte) 0x64;
        final byte SECTION_10 = (byte) 0x40;
        final byte SECTION_11 = (byte) 0x7F;
        
        switch (b0) {
            case SECTION_1:
                // 10.x.x.x/8
                return true;
            case SECTION_2:
                // 172.16.x.x - 172.31.x.x
                if (b1 >= SECTION_3 && b1 <= SECTION_4) {
                    return true;
                }
                break;
            case SECTION_5:
                // 192.168.x.x/16
                if (b1 == SECTION_6) {
                    return true;
                }
                break;
            case SECTION_7:
                // 169.254.x.x/16 - 链路本地地址
                if (b1 == SECTION_8) {
                    return true;
                }
                break;
            case SECTION_9:
                // 100.64.x.x - 100.127.x.x (运营商级 NAT，包括云元数据地址如 100.100.100.200)
                if (b1 >= SECTION_10 && b1 <= SECTION_11) {
                    return true;
                }
                break;
            default:
                break;
        }
        return false;
    }

    /**
     * 将IPv4地址转换成字节
     *
     * @param text IPv4地址
     * @return byte 字节
     */
    public static byte[] textToNumericFormatV4(String text) {
        if (text.isEmpty()) {
            return null;
        }

        byte[] bytes = new byte[4];
        String[] elements = text.split("\\.", -1);
        try {
            long l;
            int i;
            switch (elements.length) {
                case 1:
                    l = Long.parseLong(elements[0]);
                    if ((l < 0L) || (l > 4294967295L)) {
                        return null;
                    }
                    bytes[0] = (byte) (int) (l >> 24 & 0xFF);
                    bytes[1] = (byte) (int) ((l & 0xFFFFFF) >> 16 & 0xFF);
                    bytes[2] = (byte) (int) ((l & 0xFFFF) >> 8 & 0xFF);
                    bytes[3] = (byte) (int) (l & 0xFF);
                    break;
                case 2:
                    l = Integer.parseInt(elements[0]);
                    if ((l < 0L) || (l > 255L)) {
                        return null;
                    }
                    bytes[0] = (byte) (int) (l & 0xFF);
                    l = Integer.parseInt(elements[1]);
                    if ((l < 0L) || (l > 16777215L)) {
                        return null;
                    }
                    bytes[1] = (byte) (int) (l >> 16 & 0xFF);
                    bytes[2] = (byte) (int) ((l & 0xFFFF) >> 8 & 0xFF);
                    bytes[3] = (byte) (int) (l & 0xFF);
                    break;
                case 3:
                    for (i = 0; i < 2; ++i) {
                        l = Integer.parseInt(elements[i]);
                        if ((l < 0L) || (l > 255L)) {
                            return null;
                        }
                        bytes[i] = (byte) (int) (l & 0xFF);
                    }
                    l = Integer.parseInt(elements[2]);
                    if ((l < 0L) || (l > 65535L)) {
                        return null;
                    }
                    bytes[2] = (byte) (int) (l >> 8 & 0xFF);
                    bytes[3] = (byte) (int) (l & 0xFF);
                    break;
                case 4:
                    for (i = 0; i < 4; ++i) {
                        l = Integer.parseInt(elements[i]);
                        if ((l < 0L) || (l > 255L)) {
                            return null;
                        }
                        bytes[i] = (byte) (int) (l & 0xFF);
                    }
                    break;
                default:
                    return null;
            }
        } catch (NumberFormatException e) {
            return null;
        }
        return bytes;
    }

}
