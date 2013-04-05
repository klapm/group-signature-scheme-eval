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

package org.iso200082.mechanisms.m4;

import org.iso200082.common.api.GroupSignatureScheme;
import org.iso200082.common.api.exceptions.SchemeException;
import org.iso200082.common.api.parties.Issuer;
import org.iso200082.common.api.parties.Linker;
import org.iso200082.common.api.parties.Verifier;
import org.iso200082.common.api.revocation.RevocationPolicy;
import org.iso200082.common.ecc.api.AsymmetricPairing;
import org.iso200082.mechanisms.m4.ds.group.M4Parameters;
import org.iso200082.mechanisms.m4.ds.group.M4PublicKey;
import org.iso200082.mechanisms.m4.parties.M4Issuer;
import org.iso200082.mechanisms.m4.parties.M4Linker;
import org.iso200082.mechanisms.m4.parties.M4Signer;
import org.iso200082.mechanisms.m4.parties.M4Verifier;

/**
 * Scheme instance for mechanism four. Acts as the knot that ties all
 * parties together.
 * 
 * This scheme can be parameterized with the following values (named
 * accordingly as in the draft standard). The identifiers are case sensitive.
 * Refer to the draft for more information.
 * 
 * <p>
 * int:
 * <ul>
 *   <li>t</li> (note that t has no effect yet as the bit length is fixed)
 * </ul>
 * 
 * String:
 * <ul>
 *   <li>hash_algorithm</li>
 * </ul>
 * </p>
 * 
 * Note that there is major room for improvement regarding the parameterization
 * of the pairing function. However, the implemented way is rather restricted
 * regarding choice of parameters, which is why this is left open at the
 * moment.
 * 
 * See "High-Speed Software Implementation of the Optimal Ate Pairing over
 * Barreto�Naehrig Curves" (Beuchat, Gonz�lez-D�az, Mitsunari, Okamoto,
 * Rodr�guez-Henr�quez and Teruya) and
 * "Faster Explicit Formulas for Computing Pairings over Ordinary Curves"
 * (Aranha, Karabina, Longa, Gebotys and L�pez)
 * for more information on that matter.
 * 
 * @see RevocationPolicy
 * @see M4Issuer
 * @see M4Signer
 * @see M4Verifier
 * @see M4Linker
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M4Scheme
<
  P
>
extends GroupSignatureScheme
{
  /** The group's public parameters */
  protected M4Parameters<P>     params;
  
  /** The group's public key */
  protected M4PublicKey<P>      gpub;
  
  /** The reovcation policy to use (given by the ID string) */
  protected RevocationPolicy policy;
  
  /** The group's issuer */
  protected M4Issuer<P>         issuer;
  
  /**
   * Ctor, instantiates the pairing function using a fixed curve (for now).
   * 
   * @param policy The revocation policy to use
   * @param pairing The pairing map to use
   */
  public M4Scheme(RevocationPolicy policy, AsymmetricPairing<P> pairing)
  {
    this.params = new M4Parameters<P>(pairing);
    this.policy = policy;
  }
  
  /**
   * Setter for the public key, set upon
   * {@link M4Issuer#createGroup(M4Parameters, M4Scheme, RevocationPolicy, 
   * boolean)}
   * 
   * @param key The public key
   */
  public void setPublicKey(M4PublicKey<P> key)
  {
    gpub = key;
  }
  
  /**
   * Getter for the group's parameters
   * @return The parameters
   */
  public M4Parameters<P> getParameters()
  {
    return params;
  }

  /**
   * Getter for the group's public key
   * @return The public key
   */
  public M4PublicKey<P> getPublicKey()
  {
    return gpub;
  }

  @Override
  public Issuer createGroup()
  {
    return createGroup(false);
  }

  @Override
  public Issuer createGroup(boolean skip_create)
  {
    return M4Issuer.createGroup(params, this, policy, skip_create);
  }

  @Override
  public Verifier getVerifier()
  {
    return new M4Verifier<P>(this, policy.anewIfLocal());
  }

  @Override
  public Linker getLinker()
  {
    return new M4Linker<P>();
  }

  @Override
  public void parameterize(String identifier, int value) throws SchemeException
  {
    if(identifier == "t")
      params.setT(value);
    else
      throw new SchemeException("No such int-parameter: " + identifier);
  }

  @Override
  public void parameterize(String identifier, String value) throws SchemeException
  {
    if(identifier == "hash_algorithm")
      params.setHashAlgorithm(value);
    else
      throw new SchemeException("No such String-parameter: " + identifier);
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
