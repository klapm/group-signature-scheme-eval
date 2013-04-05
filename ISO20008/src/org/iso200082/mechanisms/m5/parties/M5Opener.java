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

package org.iso200082.mechanisms.m5.parties;

import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.parties.Opener;
import org.iso200082.mechanisms.m5.M5Scheme;
import org.iso200082.mechanisms.m5.ds.M5Signature;
import org.iso200082.mechanisms.m5.ds.group.M5MembershipOpeningKey;
import org.iso200082.mechanisms.m5.ds.group.M5OpenerProperties;
import org.iso200082.mechanisms.m5.ds.group.M5Parameters;
import org.iso200082.mechanisms.m5.protocol.M5Protocol;

/**
 * Opening authority of mechanism five. Provides means to open a signature
 * and thus reveal the true identity of the signer.
 *  
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @param <P> The primitive Type to use
 * 
 * @see M5Signer
 * @see M5Verifier
 * @see M5Scheme
 * @see M5Issuer
 */
public class M5Opener
<
  P
>
implements Opener
{
  /** The corresponding scheme */
  protected M5Scheme<P> scheme;
  
  /** The group membership opening key */
  protected M5MembershipOpeningKey<P> gmok;

  /**
   * Ctor, sets the scheme and opener private key
   * 
   * @param scheme The corresponding {@link M5Scheme} instance
   * @param gmok The group membership opening key
   */
  public M5Opener(M5Scheme<P> scheme, M5MembershipOpeningKey<P> gmok)
  {
    this.scheme = scheme;
    this.gmok   = gmok;
  }

  /**
   * Group 'creation' in terms of the opener setup. Group creation in
   * mechanism five consists of two steps, involving both the actual issuer
   * and the opening authority (so both can have their private keys).
   * 
   * @param params The group's public parameters
   * @param scheme The correspondig {@link M5Scheme} instance
   * 
   * @return A new {@link M5Opener} instance
   */
  public static <P> M5Opener<P> 
  createGroup(M5Parameters<P> params, M5Scheme<P> scheme)
  {
    M5OpenerProperties<P> props = M5Protocol.groupMembershipOpenerSetup(params);
    scheme.setOpenerPublicKey(props.getOpenerPublicKey());
    return new M5Opener<P>(scheme, props.getMembershipOpeningKey());
  }

  @Override
  @SuppressWarnings("unchecked")
  public String openSignature(Signature signature)
  {
    if(!(signature instanceof M5Signature))
      return null;
    
    return M5Protocol.openSignature((M5Signature<P>) signature, gmok, scheme);
  }
  
}
