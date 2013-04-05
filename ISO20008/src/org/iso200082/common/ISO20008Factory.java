/*
 * This file is part of an unofficial ISO20008-2.2 sample implementation to
 * evaluate certain schemes for their applicability on Android-based mobile
 * devices. The source is licensed under the modified 3-clause BSD license,
 * see the readme.
 * 
 * The code was published in conjunction with the publication called 
 * "Group Signatures on Mobile Devices: Practical Experiences" by
 * Potzmader, Winter, Hein, Hanser, Teufl and Chen
 */

package org.iso200082.common;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import org.iso200082.common.api.GroupSignatureScheme;
import org.iso200082.common.api.SchemeFactory;
import org.iso200082.common.api.exceptions.SchemeException;
import org.iso200082.common.api.revocation.NoRevocationPolicy;
import org.iso200082.common.api.revocation.RevocationPolicy;
import org.iso200082.common.ecc.api.AsymmetricPairing;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.common.ecc.num.FqBigInteger;
import org.iso200082.common.ecc.num.FqFixedWidth;
import org.iso200082.common.ecc.num.FqMontgomeryBigInteger;
import org.iso200082.common.ecc.num.FqMontgomeryFixedWidth;
import org.iso200082.common.ecc.pairings.Ate;
import org.iso200082.common.util.IntegerUtil;
import org.iso200082.mechanisms.m1.M1Scheme;
import org.iso200082.mechanisms.m1.revocation.M1GlobalPrivateKeyPolicy;
import org.iso200082.mechanisms.m1.revocation.M1LocalBlacklistingPolicy;
import org.iso200082.mechanisms.m1.revocation.M1LocalPrivateKeyPolicy;
import org.iso200082.mechanisms.m4.M4Scheme;
import org.iso200082.mechanisms.m4.revocation.M4CredentialUpdatePolicy;
import org.iso200082.mechanisms.m4.revocation.M4GlobalPrivateKeyPolicy;
import org.iso200082.mechanisms.m4.revocation.M4GlobalSignaturePolicy;
import org.iso200082.mechanisms.m4.revocation.M4LocalBlacklistingPolicy;
import org.iso200082.mechanisms.m4.revocation.M4LocalPrivateKeyPolicy;
import org.iso200082.mechanisms.m4.revocation.M4LocalSignaturePolicy;
import org.iso200082.mechanisms.m5.M5Scheme;
import org.iso200082.mechanisms.m5.revocation.M5CredentialUpdatePolicy;


/**
 * Concrete {@link SchemeFactory} implementation to be used with this
 * API implementation. Here, all schemes are registered and assigned with an id.
 * 
 * An ID always contains the mechanism ID (m<x>, with 1 <= x <= 7), the
 * revocation policy abbreviation( bl = blacklist, cu = credential update,
 * lpk = local private key revocation, gpk = global private key revocation,
 * ls = local signature revocation, gs = global signature revocation,
 * nr = no revocation), the identifier for the underlying primitive
 * implementation (bigint = java.math.BigInteger, fixedwidth = custom 
 * fixed-width implementation) and (optionally) "mont" for transformation to the
 * montgomery domain (pairing only). Finally, the point multiplication method
 * can be defined for the mechanisms 4 and 5. If "-affine" is specified, then
 * plain affine scalar multiplication is used, if "-mixed" is specified, then
 * a mixture of affine and jacobian coordinates is used.
 * 
 * Be warned: There's some weird hackery ahead in this class.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @see SchemeFactory
 */
public class ISO20008Factory extends SchemeFactory
{
  /** map of known schemes */
  private Map<String, SchemePolicyBag<?>> schemes;
    
  /**
   * Simple container tying scheme and policy together.
   * 
   * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
   * @version 1.0
   */
  private class SchemePolicyBag<P>
  {
    /** The scheme */
    private Class<? extends GroupSignatureScheme> scheme;
    
    /** The corresponding revocation polcy */
    private Class<? extends RevocationPolicy>     policy;

    /** The corresponding revocation polcy */
    private Class<? extends Fq<P>> Fq;
    
    /**
     * Ctor, filling in the blanks.
     * 
     * @param scheme The scheme
     * @param policy The corresponding policy
     * @param Fq     The primitive implementation
     */
    public SchemePolicyBag(Class<? extends GroupSignatureScheme> scheme,
                           Class<? extends RevocationPolicy>     policy,
                           Class<? extends Fq<P>> Fq)
    {
      this.scheme     = scheme;
      this.policy     = policy;
      this.Fq         = Fq;
    }

    /**
     * Getter for the scheme
     * @return The scheme
     */
    public Class<? extends GroupSignatureScheme> getScheme()
    {
      return this.scheme;
    }

    /**
     * Getter for the policy
     * @return The corresponding revocation policy
     */
    public Class<? extends RevocationPolicy> getPolicy()
    {
      return this.policy;
    }
    
    public Class<? extends Fq<P>> getFq()
    {
      return this.Fq;
    }
  }
   
  /**
   * Ctor, registers all known schemes
   */
  public ISO20008Factory()
  {
    schemes = new HashMap<String, SchemePolicyBag<?>>();
    schemePermute();
  }
  
  @SuppressWarnings({ "unchecked", "rawtypes" })
  private void schemePermute()
  {    
    Object[][] schemes = new Object[][] { 
     new Object[] { "m1-nr",  M1Scheme.class, NoRevocationPolicy.class        },
     new Object[] { "m1-bl",  M1Scheme.class, M1LocalBlacklistingPolicy.class },
     new Object[] { "m1-lpk", M1Scheme.class, M1LocalPrivateKeyPolicy.class   },
     new Object[] { "m1-gpk", M1Scheme.class, M1GlobalPrivateKeyPolicy.class  },
     new Object[] { "m4-nr",  M4Scheme.class, NoRevocationPolicy.class        },
     new Object[] { "m4-bl",  M4Scheme.class, M4LocalBlacklistingPolicy.class },
     new Object[] { "m4-lpk", M4Scheme.class, M4LocalPrivateKeyPolicy.class   },
     new Object[] { "m4-gpk", M4Scheme.class, M4GlobalPrivateKeyPolicy.class  },
     new Object[] { "m4-ls",  M4Scheme.class, M4LocalSignaturePolicy.class    },
     new Object[] { "m4-gs",  M4Scheme.class, M4GlobalSignaturePolicy.class   },
     new Object[] { "m4-cu",  M4Scheme.class, M4CredentialUpdatePolicy.class  },
     new Object[] { "m5-nr",  M5Scheme.class, NoRevocationPolicy.class        },
     new Object[] { "m5-cu",  M5Scheme.class, M5CredentialUpdatePolicy.class  },
    };
    
    Object[][] primitive_implementations = new Object[][] {
     new Object[] { "bigint",      FqBigInteger.class               },
     new Object[] { "mont-bigint", FqMontgomeryBigInteger.class     },
     new Object[] { "fixedwidth",  FqFixedWidth.class               },
     new Object[] { "mont-fixedwidth", FqMontgomeryFixedWidth.class },
    };    
        
    for(Object[] mechanism : schemes) {
      String identifier = (String) mechanism[0];
      if(!identifier.contains("m1"))
      {        
        for(Object[] primitive : primitive_implementations)
        {
          String primitive_id = (String) primitive[0];
          if(identifier.contains("m4"))
          {
            registerScheme(identifier + "-" + primitive_id + "-affine",
                            (Class) mechanism[1],
                            (Class) mechanism[2],
                            (Class) primitive[1], false);
            registerScheme(identifier + "-" + primitive_id + "-mixed",
                            (Class) mechanism[1],
                            (Class) mechanism[2],
                            (Class) primitive[1], true);
          }
          // m5, no montgomery stuff (no pairing)
          else if(!primitive_id.contains("mont"))
          {
            registerScheme(identifier + "-" + primitive_id + "-affine",
                          (Class) mechanism[1],
                          (Class) mechanism[2],
                          (Class) primitive[1], false);
            registerScheme(identifier + "-" + primitive_id + "-mixed",
                          (Class) mechanism[1],
                          (Class) mechanism[2],
                          (Class) primitive[1], true);
          }
        }
      }
      else // m1 is bigint only (overhead is negligible there) 
      {
        registerScheme(identifier, (Class) mechanism[1],
                                   (Class) mechanism[2], null, null);
      }
    }
  }
  
  /**
   * Helper to register a new scheme
   * 
   * @param id Scheme-ID
   * @param scheme Concrete scheme class
   * @param policy Corresponding revocation policy
   * @param Fq The concrete primitive implementation
   * @param mixed_mode Whether to use plain affine point multiplication or
   *                   a mix of jacobian and affine coords
   */
  public <P> void registerScheme(String id,
                                 Class<? extends GroupSignatureScheme> scheme,
                                 Class<? extends RevocationPolicy>     policy,
                                 Class<? extends Fq<P>> Fq,
                                 Boolean mixed_mode)
  {
    schemes.put(id, new SchemePolicyBag<P>(scheme, policy, Fq));
  } 
  
  @Override
  public GroupSignatureScheme loadScheme(String kind) throws SchemeException
  {
    kind = kind.toLowerCase();
    if(!schemes.containsKey(kind))
      throw new SchemeException("Unknown Mechanism");
    
    try {
      SchemePolicyBag<?> bag = schemes.get(kind);
      RevocationPolicy   plc = bag.getPolicy().newInstance();
      
      boolean mixed_mode = !kind.contains("affine"); // mixed = default
      
      GroupSignatureScheme scheme = null;
      if(kind.contains("m4-"))
      {
        Random rnd = new SecureRandom();
        rnd.setSeed(System.nanoTime());
        AsymmetricPairing<?> pairing = 
          getAtePairing(bag.getFq(), rnd, mixed_mode);
        scheme = bag.getScheme()
            .getConstructor(new Class<?>[]
                           { RevocationPolicy.class, AsymmetricPairing.class })
            .newInstance(plc, pairing);      
      }
      else if(kind.contains("m5-"))
      {
        Random rnd = new SecureRandom();
        rnd.setSeed(System.nanoTime());
        Fq<?> fact = bag.getFq()
                        .getConstructor(new Class<?>[] 
                                       { Random.class, BigInteger.class })
                        .newInstance(rnd, BigInteger.ONE /* dummy */);
        scheme = bag.getScheme()
                    .getConstructor(new Class<?>[]
                                   { RevocationPolicy.class, Fq.class, 
                                     boolean.class })
                    .newInstance(plc, fact, mixed_mode);
      }
      else
        scheme = bag.getScheme()
                    .getConstructor(new Class<?>[]{ RevocationPolicy.class })
                    .newInstance(plc);
      
      plc.setScheme(scheme);
      return scheme;
    }
    catch(Exception e) {
      throw new SchemeException(e);
    }
  }
  
  /*
   * Getter for the used pairing map 
   */
  private <P> AsymmetricPairing<P>
  getAtePairing(Class<? extends Fq<P>> Fq, Random rnd, boolean mixed_mode)
  throws Exception
  {    
    BigInteger b   = IntegerUtil.TWO;
    BigInteger xi0 = IntegerUtil.ONE;
    BigInteger xi1 = IntegerUtil.ONE;
    BigInteger q   = new BigInteger("16798108731015832284940804142231733909" +
                                    "889187121439069848933715426072753864723");
    BigInteger r   = new BigInteger("16798108731015832284940804142231733909" +
                                    "759579603404752749028378864165570215949");
    BigInteger bt  = new BigInteger("-1");
    BigInteger t   = new BigInteger("-4647714815446351873");


    Fq<P> fact = Fq.getConstructor(new Class<?>[] 
                                   { Random.class, BigInteger.class })
                   .newInstance(rnd, q);
    
    return new Ate<P>(rnd, q, r, b, t, bt, xi0, xi1, fact, mixed_mode);
  }

  @Override
  public Set<String> getSupportedSchemes()
  {
    return schemes.keySet();
  }

}
