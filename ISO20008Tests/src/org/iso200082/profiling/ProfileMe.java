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

package org.iso200082.profiling;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.security.SecureRandom;
import java.util.Random;

import org.iso200082.common.ISO20008Factory;
import org.iso200082.common.api.GroupSignatureScheme;
import org.iso200082.common.api.SchemeSelector;
import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.parties.Issuer;
import org.iso200082.common.api.parties.Signer;
import org.iso200082.common.api.parties.Verifier;


/**
 * Simple profile class. Execute with jVisualVM to measure runtime/memory
 * consumption.
 * 
 * There is an eclipse jVisualVM launcher available, check out 
 * http://visualvm.java.net/eclipse-launcher.html
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 */
public class ProfileMe
{
  private static Random rnd = new SecureRandom();
  
  static {
    rnd.setSeed(System.currentTimeMillis());
  }
    
  /**
   * Runs the profiled application
   * 
   * @param args None
   * @throws IOException on Error
   */
  public static void main(String[] args) throws IOException
  {
    printMemStats();
    
    String cmd;
    BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
    
    Issuer    issuer;
    Signer    signer;
    Verifier  verifier;
    Signature sig;
    while(true)
    {
      System.out.println("Choose scheme");
      System.out.println("Available schemes: " + 
                         new ISO20008Factory().getSupportedSchemes());
      cmd = in.readLine();
      if(cmd.equals("exit") || cmd.equals("quit") || cmd.equals("bye"))
      {
        System.out.println("exiting");
        break;
      }

      if(cmd.equals("stats")) {
        printMemStats();
        continue; 
      }
      
      try {
        GroupSignatureScheme scheme = SchemeSelector.load(cmd);
        System.out.println("Enter create/join/sign/verify/revoke " +
        		               "to perform the requested operation, " +
        		               "or exit to quit");
        issuer = null; signer = null; verifier = null; sig = null;
        while(true)
        {
          cmd = in.readLine();
          if(cmd.equals("exit") || cmd.equals("quit") || cmd.equals("bye"))
          {
            System.out.println("Back to scheme-choice-mode");
            System.out.println("Enter exit again to quit");
            break;
          }

          if(cmd.equals("stats")) {
            printMemStats();
            continue; 
          }
          
          try {
          
            if(cmd.startsWith("create"))
            {
              String[] num = cmd.split(" ");
              if(num.length > 1) {
                int keylen = 1024;
                try{
                  keylen = Integer.parseInt(num[1]);
                } catch(Exception e) {
                  System.out.println("Invalid key length, try again");
                }
                scheme.parameterize("keylen", keylen);
                issuer   = scheme.createGroup();
                verifier = scheme.getVerifier();
                signer   = null;
                sig      = null;
              }
              else { // defaults
                issuer   = scheme.createGroup();
                verifier = scheme.getVerifier();
                signer   = null;
                sig      = null;
              }
            }
            else if(cmd.equals("join"))
            {
              if(issuer == null)
                System.out.println("create first");
              else
                signer = issuer.addMember("dummy");
            }
            else if(cmd.equals("sign"))
            {
              if(issuer == null)
                System.out.println("Create and join first");
              else if(signer == null)
                System.out.println("Join first");
              else
                sig = signer.signMessage("bla");
            }
            else if(cmd.equals("verify"))
            {
              if(issuer == null)
                System.out.println("Create, join and sign first");
              else if(signer == null)
                System.out.println("Join and sign first");
              else if(sig == null)
                System.out.println("Sign first");
              else
                if(!verifier.isSignatureValid("bla",
                                              signer.getLinkingBase(), sig))
                  System.out.println("Whoops, signature invalid?");
            }
            else if(cmd.equals("revoke"))
            {
              // not implemented
            }
            else
              System.out.println("Unknown command, try again");
          }
          catch(Exception e)
          {
            System.out.println("Error: " + e.getMessage());
          }
           
          System.out.println("Done.");
        }
        
        
      } catch(Exception e)
      {
        System.out.println("Unknown scheme, try again");
      }
    }
  }
  
  private static void printMemStats()
  {
    MemoryMXBean membean = ManagementFactory.getMemoryMXBean();
    System.out.println("Max Heap:     " + membean.getHeapMemoryUsage().getMax() / 1024 + "kb");
    System.out.println("Used Heap:    " + membean.getHeapMemoryUsage().getUsed()/ 1024 + "kb");
    System.out.println("Max PermGen:  " + membean.getNonHeapMemoryUsage().getMax()/ 1024 + "kb");
    System.out.println("Used PermGen: " + membean.getNonHeapMemoryUsage().getUsed()/ 1024 + "kb");
  }
}
