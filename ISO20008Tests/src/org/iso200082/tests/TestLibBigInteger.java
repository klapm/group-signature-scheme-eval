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

import org.junit.Test;


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
public class TestLibBigInteger extends TestLib
{

  static {
    M1_NO_REVOCATION     = "m1-nr";
    M1_BLACKLISTING      = "m1-bl";
    M1_LPK               = "m1-lpk";
    M1_GPK               = "m1-gpk";
    
    // replace "affine" with "mixed" for mixed-mode pt. mult.
    M4_NO_REVOCATION     = "m4-nr-bigint-affine";
    M4_LS                = "m4-ls-bigint-affine";
    M4_GS                = "m4-gs-bigint-affine";
    M4_GPK               = "m4-gpk-bigint-affine";
    M4_LPK               = "m4-lpk-bigint-affine";
    M4_BLACKLISTING      = "m4-bl-bigint-affine";
    M4_CREDENTIAL_UPDATE = "m4-cu-bigint-affine";
    
    M5_NO_REVOCATION     = "m5-nr-bigint-affine";
    M5_CREDENTIAL_UPDATE = "m5-cu-bigint-affine";
  }
  
  @Override
  @Test
  public void testCredentialUpdate()
  {
    super.testCredentialUpdate();
  }
  
  @Override
  @Test
  public void testGlobalPrivateKeyRevocation()
  {
    super.testGlobalPrivateKeyRevocation();
  }
  
  @Override
  @Test
  public void testGlobalSignatureRevocation()
  {
    super.testGlobalSignatureRevocation();
  }
  
  @Override
  @Test
  public void testLocalBlacklistRevocation()
  {
    super.testLocalBlacklistRevocation();
  }
  
  @Override
  @Test
  public void testLocalPrivateKeyRevocation()
  {
    super.testLocalPrivateKeyRevocation();
  }
  
  @Override
  @Test
  public void testLocalSignatureRevocation()
  {
    super.testLocalSignatureRevocation();
  }
  
  @Override
  @Test
  public void testNoRevocation()
  {
    super.testNoRevocation();
  }
  
  @Override
  @Test
  public void testLib()
  {
    super.testLib();
  }
  
  @Override
  @Test
  public void testOpening()
  {
    super.testOpening();
  }

}
