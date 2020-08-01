package lsieun.crypto.asym.ecc.test;

import lsieun.crypto.asym.ecc.ECCUtils;
import lsieun.crypto.signature.dsa_ecc.ECDSASample;
import lsieun.crypto.asym.ecc.Point;
import lsieun.utils.BigUtils;

import java.math.BigInteger;

public class A_PublicPoint {
    public static void main(String[] args) {
        // 第一步，在椭圆曲线上，确定方程参数a和p
        BigInteger p = BigUtils.toBigInteger(ECDSASample.P);
        BigInteger a = new BigInteger("-3");

        // 第二步，在椭圆曲线上，确定Generator点坐标gx和gy
        BigInteger gx = BigUtils.toBigInteger(ECDSASample.gx);
        BigInteger gy = BigUtils.toBigInteger(ECDSASample.gy);
        Point G = new Point(gx, gy);

        // 第三步，在椭圆曲线上，进行乘法运算
        // 使用private key进行测试
        BigInteger private_key = BigUtils.toBigInteger(ECDSASample.w);
        Point public_point = ECCUtils.multiply_point(G, private_key, a, p);
        System.out.println(public_point.x.toString(16).toUpperCase());
        System.out.println(public_point.y.toString(16).toUpperCase());

        // 使用k进行测试
        BigInteger k = BigUtils.toBigInteger(ECDSASample.k);
        Point kG = ECCUtils.multiply_point(G, k, a, p);
        System.out.println(kG.x.toString(16).toUpperCase());
        System.out.println(kG.y.toString(16).toUpperCase());
    }
}
