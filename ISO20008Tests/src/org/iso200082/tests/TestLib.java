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

package org.iso200082.tests;


import java.math.BigInteger;

import junit.framework.Assert;

import org.iso200082.common.api.GroupSignatureScheme;
import org.iso200082.common.api.SchemeSelector;
import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.exceptions.NotSupportedByRevocationPolicyException;
import org.iso200082.common.api.exceptions.SchemeException;
import org.iso200082.common.api.parties.CarelessSigner;
import org.iso200082.common.api.parties.Issuer;
import org.iso200082.common.api.parties.Opener;
import org.iso200082.common.api.parties.Signer;
import org.iso200082.common.api.parties.Verifier;

/**
 * Library testing code, used as a user would, maybe.
 * So, below are some usage examples alongside their expected results.
 * 
 * Most tests are labeled something like test[somerevocationprocedure], but
 * a revocation tests runs through all phases (create / join / sign / verify
 * / revoke) so it tests more than just isolated revocation.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 */
public class TestLib
{
  private static final boolean SKIP_CREATE = true;
  
  private static final String TEST_MESSAGE  = "my name is max power.";
  private static final String TEST_MESSAGE2 = "yet another message";
  
  protected static String M1_NO_REVOCATION;
  protected static String M1_BLACKLISTING;
  protected static String M1_LPK;
  protected static String M1_GPK;
  
  protected static String M4_NO_REVOCATION;
  protected static String M4_LS;
  protected static String M4_GS;
  protected static String M4_GPK;
  protected static String M4_LPK;
  protected static String M4_BLACKLISTING;
  protected static String M4_CREDENTIAL_UPDATE;
  
  protected static String M5_NO_REVOCATION;
  protected static String M5_CREDENTIAL_UPDATE;

  public void testLib()
  {
    try
    {
      GroupSignatureScheme scheme = SchemeSelector.load(M1_NO_REVOCATION);
      Issuer   issuer  = scheme.createGroup(SKIP_CREATE);
      Signer   johndoe = issuer.addMember("JohnDoe");
      Verifier janedoe = scheme.getVerifier();
      Assert.assertTrue(janedoe.isSignatureValid("bla", 
                                johndoe.getLinkingBase(), 
                                johndoe.signMessage("bla")));
    } catch (SchemeException e)
    {
      e.printStackTrace();
      Assert.fail("Exception = bad.");
    }
  }
  
  public void testCredentialUpdate()
  {
    try
    {
      testCredentialUpdateRun(SchemeSelector.load(M4_CREDENTIAL_UPDATE));
      testCredentialUpdateRun(getM5WithShortKeyLen(M5_CREDENTIAL_UPDATE));
    } catch (SchemeException e)
    {
      e.printStackTrace();
      Assert.fail("Exception = bad.");
    }
  }
  
  public void testLocalBlacklistRevocation()
  {
    try
    {
      testBlacklistingRun(SchemeSelector.load(M4_BLACKLISTING));
      testNoRevocationRun(getM1WithShortKeyLen(M1_BLACKLISTING));
    } catch (SchemeException e)
    {
      e.printStackTrace();
      Assert.fail("Exception = bad.");
    }
  }
  
  public void testLocalPrivateKeyRevocation()
  {
    try
    {
      testLocalPrivateKeyRevocationRun(SchemeSelector.load(M4_LPK));
      testLocalPrivateKeyRevocationRun(getM1WithShortKeyLen(M1_LPK));
    } catch (SchemeException e)
    {
      e.printStackTrace();
      Assert.fail("Exception = bad.");
    }
  }
  
  public void testGlobalPrivateKeyRevocation()
  {
    try
    {
      testGlobalPrivateKeyRevocationRun(SchemeSelector.load(M4_GPK));
      testGlobalPrivateKeyRevocationRun(getM1WithShortKeyLen(M1_GPK));
    } catch (SchemeException e)
    {
      e.printStackTrace();
      Assert.fail("Exception = bad.");
    }
  }
  
  public void testLocalSignatureRevocation()
  {
    try
    {
      testLocalSignatureRevocationRun(SchemeSelector.load(M4_LS));
    } catch (SchemeException e)
    {
      e.printStackTrace();
      Assert.fail("Exception = bad.");
    }
  }
  
  public void testGlobalSignatureRevocation()
  {
    try
    {
      testGlobalSignatureRevocationRun(SchemeSelector.load(M4_LS));
    } catch (SchemeException e)
    {
      e.printStackTrace();
      Assert.fail("Exception = bad.");
    }
  }
  
  public void testNoRevocation()
  {
    try
    {
      testNoRevocationRun(SchemeSelector.load(M4_NO_REVOCATION));
      testNoRevocationRun(getM1WithShortKeyLen(M1_NO_REVOCATION));
      testNoRevocationRun(getM5WithShortKeyLen(M5_NO_REVOCATION));
    } catch (SchemeException e)
    {
      e.printStackTrace();
      Assert.fail("Exception = bad.");
    }
  }
  
  public void testOpening()
  {
    try
    {
      GroupSignatureScheme scheme = getM5WithShortKeyLen(M5_NO_REVOCATION);
      Issuer      issuer = scheme.createGroup(SKIP_CREATE);
      Signer      member = issuer.addMember("member1");
      Verifier  verifier = scheme.getVerifier();
      Opener      opener = scheme.getOpener();
      
      Signature sig1 = member.signMessage(TEST_MESSAGE);
      Assert.assertTrue(verifier.isSignatureValid(TEST_MESSAGE, sig1));
      Assert.assertEquals("member1", opener.openSignature(sig1));
    }
    catch (Exception e)
    {
      e.printStackTrace();
      Assert.fail("Exception = bad.");
    }   
  }
  
  private void testCredentialUpdateRun(GroupSignatureScheme scheme)
  {
    try
    {
      Issuer    issuer  = scheme.createGroup(SKIP_CREATE);
      Signer    member1 = issuer.addMember("member1");
      Signer    member2 = issuer.addMember("member2");
      Verifier verifier = scheme.getVerifier();
      
      Signature sig1 = member1.signMessage(TEST_MESSAGE);
      Signature sig2 = member2.signMessage(TEST_MESSAGE);
      Assert.assertTrue(verifier.isSignatureValid(TEST_MESSAGE,
                                 member1.getLinkingBase(), sig1));
      Assert.assertTrue(verifier.isSignatureValid(TEST_MESSAGE,
                                 member2.getLinkingBase(), sig2));
      
      issuer.doCredentialUpdate(member1);

      // m1 has new credentials
      Signature sig3 = member1.signMessage(TEST_MESSAGE); 
      
      // m2 has old credentials
      Signature sig4 = member2.signMessage(TEST_MESSAGE); 
      
      Assert.assertFalse(verifier.isSignatureValid(TEST_MESSAGE,
                                  member1.getLinkingBase(), sig1));
      Assert.assertFalse(verifier.isSignatureValid(TEST_MESSAGE,
                                  member2.getLinkingBase(), sig2));
      Assert.assertFalse(verifier.isSignatureValid(TEST_MESSAGE,
                                  member2.getLinkingBase(), sig4));
      Assert.assertTrue(verifier.isSignatureValid(TEST_MESSAGE,
                                  member1.getLinkingBase(), sig3));

      Signer member3 = issuer.addMember("member3");
      Signature sig5 = member3.signMessage(TEST_MESSAGE);
      Assert.assertTrue(verifier.isSignatureValid(TEST_MESSAGE,
                                 member3.getLinkingBase(), sig5));
      
    } catch (Exception e)
    {
      e.printStackTrace();
      Assert.fail("Exception = bad.");
    }
    
  }
  
  private void testBlacklistingRun(GroupSignatureScheme scheme)
  {
    try
    {
      Issuer    issuer   = scheme.createGroup(SKIP_CREATE);
      Signer    member1  = issuer.addMember("member1");
      Signer    member2  = issuer.addMember("member2");
      Verifier verifier1 = scheme.getVerifier();
      Verifier verifier2 = scheme.getVerifier();
      
      Signature sig1 = member1.signMessage(TEST_MESSAGE);
      Signature sig2 = member2.signMessage(TEST_MESSAGE);
      Assert.assertTrue(verifier1.isSignatureValid(TEST_MESSAGE,
                                  member1.getLinkingBase(), sig1));
      Assert.assertTrue(verifier2.isSignatureValid(TEST_MESSAGE,
                                  member2.getLinkingBase(), sig2));
      Assert.assertTrue(verifier1.blacklist(member1.getLinkingBase(), sig1));
      
      Signature sig3 = member1.signMessage(TEST_MESSAGE);
      Signature sig4 = member2.signMessage(TEST_MESSAGE);

      Assert.assertFalse(verifier1.isSignatureValid(TEST_MESSAGE,
                                   member1.getLinkingBase(), sig1));
      Assert.assertTrue(verifier2.isSignatureValid(TEST_MESSAGE,
                                   member1.getLinkingBase(), sig1));
      Assert.assertTrue(verifier1.isSignatureValid(TEST_MESSAGE,
                                   member2.getLinkingBase(), sig2));
      Assert.assertTrue(verifier1.isSignatureValid(TEST_MESSAGE,
                                   member2.getLinkingBase(), sig4));
      Assert.assertTrue(verifier2.isSignatureValid(TEST_MESSAGE,
                                   member2.getLinkingBase(), sig4));
      Assert.assertFalse(verifier1.isSignatureValid(TEST_MESSAGE,
                                   member1.getLinkingBase(), sig3));
      Assert.assertTrue(verifier2.isSignatureValid(TEST_MESSAGE,
                                   member1.getLinkingBase(), sig3));
      
      
    } catch (Exception e)
    {
      e.printStackTrace();
      Assert.fail("Exception = bad.");
    }
    
  }
  
  private void testLocalPrivateKeyRevocationRun(GroupSignatureScheme scheme)
  {
    try
    {
      Issuer            issuer   = scheme.createGroup(SKIP_CREATE);
      CarelessSigner    member1  = (CarelessSigner) issuer.addMember("member1");
      Signer            member2  = issuer.addMember("member2");
      Verifier        verifier1  = scheme.getVerifier();
      Verifier        verifier2  = scheme.getVerifier();
      
      Signature sig1 = member1.signMessage(TEST_MESSAGE);
      Signature sig2 = member2.signMessage(TEST_MESSAGE);
      Assert.assertTrue(verifier1.isSignatureValid(TEST_MESSAGE,
                                  member1.getLinkingBase(), sig1));
      Assert.assertTrue(verifier2.isSignatureValid(TEST_MESSAGE,
                                  member2.getLinkingBase(), sig2));
      Assert.assertTrue(verifier1.revokeKey(member1.getDrunkAndTellSecrets()));
      
      Signature sig3 = member1.signMessage(TEST_MESSAGE);
      Signature sig4 = member2.signMessage(TEST_MESSAGE);

      Assert.assertFalse(verifier1.isSignatureValid(TEST_MESSAGE,
                                   member1.getLinkingBase(), sig1));
      Assert.assertTrue(verifier2.isSignatureValid(TEST_MESSAGE,
                                  member1.getLinkingBase(), sig1));
      Assert.assertTrue(verifier1.isSignatureValid(TEST_MESSAGE,
                                  member2.getLinkingBase(), sig2));
      Assert.assertTrue(verifier1.isSignatureValid(TEST_MESSAGE,
                                  member2.getLinkingBase(), sig4));
      Assert.assertTrue(verifier2.isSignatureValid(TEST_MESSAGE,
                                  member2.getLinkingBase(), sig4));
      Assert.assertFalse(verifier1.isSignatureValid(TEST_MESSAGE,
                                   member1.getLinkingBase(), sig3));
      Assert.assertTrue(verifier2.isSignatureValid(TEST_MESSAGE,
                                   member1.getLinkingBase(), sig3));
      
      
    } catch (Exception e)
    {
      e.printStackTrace();
      Assert.fail("Exception = bad.");
    }    
  }
  
  private void testGlobalPrivateKeyRevocationRun(GroupSignatureScheme scheme)
  {
    try
    {
      Issuer            issuer   = scheme.createGroup(SKIP_CREATE);
      CarelessSigner    member1  = (CarelessSigner) issuer.addMember("member1");
      Signer            member2  = issuer.addMember("member2");
      Verifier        verifier1  = scheme.getVerifier();
      Verifier        verifier2  = scheme.getVerifier();
      
      Signature sig1 = member1.signMessage(TEST_MESSAGE);
      Signature sig2 = member2.signMessage(TEST_MESSAGE);
      Assert.assertTrue(verifier1.isSignatureValid(TEST_MESSAGE,
                                  member1.getLinkingBase(), sig1, member1));
      Assert.assertTrue(verifier2.isSignatureValid(TEST_MESSAGE,
                                  member2.getLinkingBase(), sig2, member2));
      Assert.assertTrue(verifier1.revokeKey(member1.getDrunkAndTellSecrets()));
      
      Signature sig3 = member1.signMessage(TEST_MESSAGE);
      Signature sig4 = member2.signMessage(TEST_MESSAGE);

      Assert.assertFalse(verifier1.isSignatureValid(TEST_MESSAGE,
                                   member1.getLinkingBase(), sig1));
      Assert.assertFalse(verifier2.isSignatureValid(TEST_MESSAGE,
                                   member1.getLinkingBase(), sig1));
      Assert.assertTrue( verifier1.isSignatureValid(TEST_MESSAGE,
                                   member2.getLinkingBase(), sig2));
      Assert.assertTrue( verifier1.isSignatureValid(TEST_MESSAGE,
                                   member2.getLinkingBase(), sig4));
      Assert.assertTrue( verifier2.isSignatureValid(TEST_MESSAGE,
                                   member2.getLinkingBase(), sig4));
      Assert.assertFalse(verifier1.isSignatureValid(TEST_MESSAGE,
                                   member1.getLinkingBase(), sig3));
      Assert.assertFalse(verifier2.isSignatureValid(TEST_MESSAGE,
                                   member1.getLinkingBase(), sig3));
      
      
    } catch (Exception e)
    {
      e.printStackTrace();
      Assert.fail("Exception = bad.");
    }    
  }
  
  private void testLocalSignatureRevocationRun(GroupSignatureScheme scheme)
  {
    try
    {
      Issuer      issuer   = scheme.createGroup(SKIP_CREATE);
      Signer      member1  = issuer.addMember("member1");
      Signer      member2  = issuer.addMember("member2");
      BigInteger     bsn1  = member1.getLinkingBase();
      BigInteger     bsn2  = member2.getLinkingBase();
      Verifier  verifier1  = scheme.getVerifier();
      Verifier  verifier2  = scheme.getVerifier();
      
      Signature sig1 = member1.signMessage(TEST_MESSAGE);
      Signature sig2 = member2.signMessage(TEST_MESSAGE);
      Assert.assertTrue(verifier1.isSignatureValid(TEST_MESSAGE,
                                                   bsn1, sig1, member1));
      Assert.assertTrue(verifier1.isSignatureValid(TEST_MESSAGE,
                                                   bsn2, sig2, member2));
      Assert.assertTrue(verifier2.isSignatureValid(TEST_MESSAGE,
                                                   bsn1, sig1, member1));
      Assert.assertTrue(verifier2.isSignatureValid(TEST_MESSAGE,
                                                   bsn2, sig2, member2));
      Assert.assertTrue(verifier1.revokeSignature(sig1));
            
      Signature sig3 = member1.signMessage(TEST_MESSAGE2);
      Signature sig4 = member2.signMessage(TEST_MESSAGE2);

      Assert.assertFalse(verifier1.isSignatureValid(TEST_MESSAGE, 
                                                    bsn1, sig1, member1));
      Assert.assertTrue( verifier2.isSignatureValid(TEST_MESSAGE, 
                                                    bsn1, sig1, member1));
      Assert.assertTrue( verifier1.isSignatureValid(TEST_MESSAGE, 
                                                    bsn2, sig2, member2));
      Assert.assertTrue( verifier1.isSignatureValid(TEST_MESSAGE2,
                                                    bsn2, sig4, member2));
      Assert.assertTrue( verifier2.isSignatureValid(TEST_MESSAGE2,
                                                    bsn2, sig4, member2));
      Assert.assertFalse(verifier1.isSignatureValid(TEST_MESSAGE2,
                                                    bsn1, sig3, member1));
      Assert.assertTrue( verifier2.isSignatureValid(TEST_MESSAGE2,
                                                    bsn1, sig3, member1));
      Assert.assertTrue(verifier2.revokeSignature(sig4));
      Assert.assertFalse(verifier2.isSignatureValid(TEST_MESSAGE2,
                                                    bsn2, sig4, member2));
      Assert.assertTrue( verifier1.isSignatureValid(TEST_MESSAGE2,
                                                    bsn2, sig4, member2));
    } catch (Exception e)
    {
      e.printStackTrace();
      Assert.fail("Exception = bad.");
    }    
  }
  
  private void testGlobalSignatureRevocationRun(GroupSignatureScheme scheme)
  {
    try
    {
      Issuer      issuer   = scheme.createGroup(SKIP_CREATE);
      Signer      member1  = issuer.addMember("member1");
      Signer      member2  = issuer.addMember("member2");
      BigInteger     bsn1  = member1.getLinkingBase();
      BigInteger     bsn2  = member2.getLinkingBase();
      Verifier  verifier1  = scheme.getVerifier();
      Verifier  verifier2  = scheme.getVerifier();
      
      Signature sig1 = member1.signMessage(TEST_MESSAGE);
      Signature sig2 = member2.signMessage(TEST_MESSAGE);
      Assert.assertTrue(verifier1.isSignatureValid(TEST_MESSAGE,
                                                   bsn1, sig1, member1));
      Assert.assertTrue(verifier1.isSignatureValid(TEST_MESSAGE,
                                                   bsn2, sig2, member2));
      Assert.assertTrue(verifier2.isSignatureValid(TEST_MESSAGE,
                                                   bsn1, sig1, member1));
      Assert.assertTrue(verifier2.isSignatureValid(TEST_MESSAGE,
                                                   bsn2, sig2, member2));
      Assert.assertTrue(verifier1.revokeSignature(sig1));
            
      Signature sig3 = member1.signMessage(TEST_MESSAGE2);
      Signature sig4 = member2.signMessage(TEST_MESSAGE2);
      Assert.assertTrue(verifier2.revokeSignature(sig3));

      Assert.assertFalse(verifier1.isSignatureValid(TEST_MESSAGE, 
                                                    bsn1, sig1, member1));
      Assert.assertFalse(verifier2.isSignatureValid(TEST_MESSAGE,
                                                    bsn1, sig1, member1));
      Assert.assertTrue( verifier1.isSignatureValid(TEST_MESSAGE,
                                                    bsn2, sig2, member2));
      Assert.assertTrue( verifier1.isSignatureValid(TEST_MESSAGE2,
                                                    bsn2, sig4, member2));
      Assert.assertTrue( verifier2.isSignatureValid(TEST_MESSAGE2,
                                                    bsn2, sig4, member2));
      Assert.assertFalse(verifier1.isSignatureValid(TEST_MESSAGE2,
                                                    bsn1, sig3, member1));
      Assert.assertFalse( verifier2.isSignatureValid(TEST_MESSAGE2,
                                                     bsn1, sig3, member1));
    } catch (Exception e)
    {
      e.printStackTrace();
      Assert.fail("Exception = bad.");
    }    
  }
  
  private void testNoRevocationRun(GroupSignatureScheme scheme)
  {
    try
    {
      Issuer      issuer   = scheme.createGroup(SKIP_CREATE);
      Signer      member1  = issuer.addMember("member1");
      Signer      member2  = issuer.addMember("member2");
      BigInteger     bsn1  = member1.getLinkingBase();
      BigInteger     bsn2  = member2.getLinkingBase();
      Verifier  verifier1  = scheme.getVerifier();
      Verifier  verifier2  = scheme.getVerifier();
      
      Signature sig1 = member1.signMessage(TEST_MESSAGE);
      Signature sig2 = member2.signMessage(TEST_MESSAGE);
      Assert.assertTrue(verifier1.isSignatureValid(TEST_MESSAGE,
                                                   bsn1, sig1, member1));
      Assert.assertTrue(verifier1.isSignatureValid(TEST_MESSAGE,
                                                   bsn2, sig2, member2));
      Assert.assertTrue(verifier2.isSignatureValid(TEST_MESSAGE,
                                                   bsn1, sig1, member1));
      Assert.assertTrue(verifier2.isSignatureValid(TEST_MESSAGE,
                                                   bsn2, sig2, member2));
      try {
        verifier1.revokeSignature(sig1);
        Assert.fail("Should've nagged.");
      }
      catch(NotSupportedByRevocationPolicyException e)
      {
        // expected.
      }
      
      Signature sig3 = member1.signMessage(TEST_MESSAGE2);
      Signature sig4 = member2.signMessage(TEST_MESSAGE2);
      
      try {
        verifier2.revokeSignature(sig3);
        Assert.fail("Should've nagged.");
      }
      catch(NotSupportedByRevocationPolicyException e)
      {
        // expected.
      }

      Assert.assertTrue(verifier1.isSignatureValid(TEST_MESSAGE, 
                                                   bsn1, sig1, member1));
      Assert.assertTrue(verifier2.isSignatureValid(TEST_MESSAGE,
                                                   bsn1, sig1, member1));
      Assert.assertTrue(verifier1.isSignatureValid(TEST_MESSAGE, 
                                                   bsn2, sig2, member2));
      Assert.assertTrue(verifier1.isSignatureValid(TEST_MESSAGE2, 
                                                   bsn2, sig4, member2));
      Assert.assertTrue(verifier2.isSignatureValid(TEST_MESSAGE2, 
                                                   bsn2, sig4, member2));
      Assert.assertTrue(verifier1.isSignatureValid(TEST_MESSAGE2, 
                                                   bsn1, sig3, member1));
      Assert.assertTrue(verifier2.isSignatureValid(TEST_MESSAGE2, 
                                                   bsn1, sig3, member1));
    } catch (Exception e)
    {
      e.printStackTrace();
      Assert.fail("Exception = bad.");
    }    
  }
  
  private GroupSignatureScheme getM1WithShortKeyLen(String type) 
  throws SchemeException
  {
    GroupSignatureScheme m1 = SchemeSelector.load(type);
    m1.parameterize("Lp", 384);
    return m1;
  }
  
  private GroupSignatureScheme getM5WithShortKeyLen(String type) 
  throws SchemeException
  {
    GroupSignatureScheme m1 = SchemeSelector.load(type);
    m1.parameterize("Kn", 512);
    return m1;
  }

}
