package org.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * @author karry
 * @date 2023/11/30 14:37
 */
public class JPBCCase {
    public static void main(String[] args) {
        // A. Generate Pairing instance based on specific elliptic curve types
        // 1. import elliptic curve parameters from properties file
        Pairing bp = PairingFactory.getPairing("a.properties");

        // 2. customize define curve parameter
        // int rBits = 160;
        // int qBits = 512;
        // TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits);
        // PairingParameters pp = pg.generate();
        // Pairing bp = PairingFactory.getPairing(pp);

        // B. choose element from group
        Field G1 = bp.getG1();
        Field Zr = bp.getZr();
        Element g = G1.newRandomElement().getImmutable();
        Element a = Zr.newRandomElement().getImmutable();
        Element b = Zr.newRandomElement().getImmutable();

        // C. compute the left half of the equation
        Element ga = g.powZn(a);
        Element gb = g.powZn(b);
        Element egg_ab = bp.pairing(ga,gb);

        // D. compute the right half of the equation
        Element egg = bp.pairing(g,g).getImmutable();
        Element ab = a.mul(b);
        Element egg_ab_p = egg.powZn(ab);

        if (egg_ab.isEqual(egg_ab_p)) {
            System.out.println("yes");
        }
        else {
            System.out.println("No");
        }
    }
}