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

package org.iso200082.mechanisms.m1;

import org.iso200082.common.api.GroupSignatureScheme;
import org.iso200082.common.api.exceptions.SchemeException;
import org.iso200082.common.api.parties.Issuer;
import org.iso200082.common.api.parties.Linker;
import org.iso200082.common.api.parties.Verifier;
import org.iso200082.common.api.revocation.AbstractRevocationPolicy;
import org.iso200082.common.api.revocation.RevocationPolicy;
import org.iso200082.mechanisms.m1.ds.group.M1Parameters;
import org.iso200082.mechanisms.m1.ds.group.M1PublicKey;
import org.iso200082.mechanisms.m1.parties.M1Issuer;
import org.iso200082.mechanisms.m1.parties.M1Linker;
import org.iso200082.mechanisms.m1.parties.M1Signer;
import org.iso200082.mechanisms.m1.parties.M1Verifier;

/**
 * Scheme instance for mechanism one. Acts as the knot that ties all
 * parties together.
 * 
 * This scheme can be parameterized with the following values (named
 * accordingly as in the draft standard). The identifiers are case sensitive.
 * Refer to the draft for more information.
 * 
 * <p>
 * int:
 * <ul>
 *   <li>k</li>
 *   <li>Lx</li>
 *   <li>LX</li>
 *   <li>Lp</li>
 *   <li>Le</li>
 *   <li>LE</li>
 * </ul>
 * 
 * String:
 * <ul>
 *   <li>hash_algorithm</li>
 * </ul>
 * 
 * Double:
 * <ul>
 *   <li>eps (or epsilon)</li>
 * </ul>
 * </p>
 * 
 * @see RevocationPolicy
 * @see AbstractRevocationPolicy
 * @see M1Issuer
 * @see M1Signer
 * @see M1Verifier
 * @see M1Linker
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M1Scheme extends GroupSignatureScheme
{
  /** Public group parameters */
  protected M1Parameters     params;
  
  /** Group public key */
  protected M1PublicKey      gpub;
  
  /** Revocation policy */
  protected RevocationPolicy policy;
  
  /**
   * Ctor, creates the scheme using a given policy
   * 
   * @param policy The revocation policy to use
   */
  public M1Scheme(RevocationPolicy policy)
  {
    this.policy = policy;
    
    // initializes to default values (= those that a recommended by the draft)
    this.params = new M1Parameters();
  }

  /**
   * Public key setter (in use as group creation is performed at 
   * {@link M1Issuer}-side)
   * @param key The new public key
   */
  public void setPublicKey(M1PublicKey key)
  {
    gpub = key;
  }
  
  /**
   * Getter for the public group parameters
   * @return The parameters
   */
  public M1Parameters getParameters()
  {
    return params;
  }
  
  /**
   * Getter for the public key
   * @return The public key
   */
  public M1PublicKey getPublicKey()
  {
    return gpub;
  }

  @Override
  public void parameterize(String identifier, int value) throws SchemeException
  {
    if(identifier == "k")
      params.setK(value);
    else if(identifier == "Lx")
      params.setLx(value);
    else if(identifier == "LX")
      params.setLX(value);
    else if(identifier == "Lp")
      params.setLp(value);
    else if(identifier == "Le")
      params.setLe(value);
    else if(identifier == "LE")
      params.setLE(value);
    else
      throw new SchemeException("No such int-parameter: " + identifier);      
  }

  @Override
  public void parameterize(String identifier, String value)
      throws SchemeException
  {
    if(identifier == "hash_algorithm")
      params.setHashAlgorithm(value);
    else
      throw new SchemeException("No such String-parameter: " + identifier);
  }

  @Override
  public void parameterize(String identifier, double value)
      throws SchemeException
  {
    if(identifier == "eps" || identifier == "epsilon")
      params.setEps(value);
    else
      throw new SchemeException("No such double-parameter: " + identifier);
  }

  @Override
  public Issuer createGroup()
  {
    return createGroup(false);
  }

  @Override
  public Issuer createGroup(boolean skip_create)
  {
    return M1Issuer.createGroup(params, this, skip_create);
  }

  @Override
  public Verifier getVerifier()
  {
    return new M1Verifier(this, policy.anewIfLocal());
  }

  @Override
  public Linker getLinker()
  {
    return new M1Linker();
  }

  @Override
  public boolean hasLinkingCapability()
  {
    return true;
  }

  @Override
  public boolean hasOpeningCapability()
  {
    return false;
  }

}
