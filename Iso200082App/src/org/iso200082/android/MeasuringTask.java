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

package org.iso200082.android;

import java.math.BigInteger;

import org.iso200082.common.api.GroupSignatureScheme;
import org.iso200082.common.api.SchemeSelector;
import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.exceptions.SchemeException;
import org.iso200082.common.api.parties.Issuer;
import org.iso200082.common.api.parties.Signer;
import org.iso200082.common.api.parties.Verifier;

import android.os.AsyncTask;
import android.widget.TextView;

/**
 * {@link AsyncTask} to carry out the whole signature scheme computations.
 * Called from {@link MainActivity} with the chosen parameterization.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class MeasuringTask extends AsyncTask<String, String, double[]> {

  /** the {@link MainActivity} status pane */
  private TextView status_view;

  /** The parent activity */
  private MainActivity activity;

  private StringBuilder status;

  /**
   * Ctor, sets parent activity and status pane
   * 
   * @param activity
   *          The parent activity
   * @param status_view
   *          Status label refernce
   */
  public MeasuringTask(MainActivity activity, TextView status_view) {
    this.status_view = status_view;
    this.activity = activity;
  }

  @Override
  protected void onPreExecute() {
    // nothing..
  }

  @Override
  protected void onProgressUpdate(String... values) {
    status.append("\n");
    status.append(values[0]);
    status_view.setText(status.toString());
  }

  @Override
  protected void onPostExecute(double[] result) {
    super.onPostExecute(result);
    activity.handResults(result);
  }

  @Override
  protected void onCancelled() {
    super.onCancelled();
    activity.notifyCancellation();
  }

  // performs the actual group signature scheme operations
  @Override
  protected synchronized double[] doInBackground(String... params)
  {
    Thread.currentThread().setPriority(Thread.MAX_PRIORITY);
    
    if (params.length < 9)
      return null;

    boolean skip_create = false;
    boolean monty       = false;
    String multmode     = "";
    int precomp_level   = 0;
    int num_iter        = 0;
    int key_len         = 0;

    try {
      num_iter = Integer.parseInt(params[2]);
      key_len = Integer.parseInt(params[3]);
    } catch (Exception e) {
      return null;
    }

    try {
      skip_create   = Boolean.parseBoolean(params[4]);
      precomp_level = Integer.parseInt(params[6]);
      monty         = Boolean.parseBoolean(params[7]);
      multmode      = params[8].contains("affine") ? "-affine" : "-mixed";
    } catch (Exception e) {
      multmode      = "-affine";
    }
    String impl = params[5];

    status = new StringBuilder(500 + 7 * num_iter);
    status.append(status_view.getText());

    String mechanism = params[0];
    String operation = params[1];
    publishProgress("----- starting new evaluation -----");
    publishProgress("Mechanism:      " + mechanism);
    publishProgress("Operation:      " + operation);
    publishProgress("Iterations:     " + num_iter);
    publishProgress("Key Length:     " + key_len);
    publishProgress("Skip creation:  " + skip_create);
    publishProgress("Arith. Impl.:   " + impl);
    publishProgress("Montgomery:     " + (monty ? "On" : "Off"));
    publishProgress("Precomputation: "
        + ((precomp_level > 1) ? "Full" : ((precomp_level == 1) ? "Partial"
                                                                : "Off")));
    publishProgress("Mult.:          " + multmode.substring(1));
    publishProgress("Heap size:      " + Runtime.getRuntime().maxMemory());
    publishProgress("Free mem:       " + Runtime.getRuntime().freeMemory());

    double[] results            = new double[num_iter];
    GroupSignatureScheme scheme = null;
    String xmont                = monty ? "mont-" : "";
    String ximpl                = ((impl.equals("eccelerate")) ? impl : 
                                  ((impl.equals("fixed w.")    ? "fixedwidth" :
                                  "bigint")));

    try {

      if (mechanism.equals("Mechanism 1"))
      {
        scheme = SchemeSelector.load("m1-nr");
        if (key_len == 512) {
          scheme.parameterize("Lp", key_len);
          scheme.parameterize("k", 160);
          scheme.parameterize("Lx", 160);
          scheme.parameterize("Le", 170);
          scheme.parameterize("LE", 420);
          scheme.parameterize("LX", 410);
          scheme.parameterize("epsilon", (double) (5 / 4));

        } else { // 1024 (2048)
          scheme.parameterize("Lp", key_len);
          scheme.parameterize("k", 160);
          scheme.parameterize("Lx", 160);
          scheme.parameterize("Le", 170);
          scheme.parameterize("LE", 420);
          scheme.parameterize("LX", 410);
          scheme.parameterize("epsilon", (double) (5 / 4));
        }
      }
      else if (mechanism.equals("Mechanism 4"))
        scheme = SchemeSelector.load("m4-nr-" + xmont + ximpl + multmode);
      else 
      {
        scheme = SchemeSelector.load("m5-nr-" + ximpl + multmode);
        scheme.parameterize("Kn", key_len);
        if (key_len == 1024) {
          scheme.parameterize("Kn", key_len);
          scheme.parameterize("K", 160);
          scheme.parameterize("Kc", 160);
          scheme.parameterize("Ks", 60);
          scheme.parameterize("Ke", 504);
          scheme.parameterize("Keprime", 60);

        } else { // 2048
          scheme.parameterize("Kn", key_len);
          scheme.parameterize("K", 224);
          scheme.parameterize("Kc", 224);
          scheme.parameterize("Ks", 112);
          scheme.parameterize("Ke", 736);
          scheme.parameterize("Keprime", 60);
        }
      }

      publishProgress("Group creation... ");
      Issuer issuer = null;
      Signer signer = null;
      Verifier verifier = null;

      if (operation.equals("Create")) {
        for (int i = 0; i < num_iter && !isCancelled(); i++) {

          long begin = System.nanoTime();
          scheme.createGroup(skip_create);
          long end = System.nanoTime();
          results[i] = (end - begin) / ((double) 1000000);
          publishProgress(i + ": " + results[i] + "ms");
        }
        publishProgress("-----          done           -----");
        return results;
      }

      issuer = scheme.createGroup(skip_create);
      publishProgress("done");

      publishProgress("Joining... ");
      if (operation.equals("Join")) {
        for (int i = 0; i < num_iter && !isCancelled(); i++) {
          long begin = System.nanoTime();
          issuer.addMember("some_one");
          long end = System.nanoTime();
          results[i] = (end - begin) / ((double) 1000000);
          publishProgress(i + ": " + results[i] + "ms");
        }
        publishProgress("-----          done           -----");
        return results;
      }

      signer = issuer.addMember("some_one");
      publishProgress("done");

      publishProgress("Signing... ");
      if (operation.equals("Sign")) {
        for (int i = 0; i < num_iter && !isCancelled(); i++) {
          if (precomp_level > 0)
            signer.precomputeSignature(precomp_level > 1);
          System.gc();
          long begin = System.nanoTime();
          signer.signMessage("aMessage");
          long end = System.nanoTime();
          results[i] = (end - begin) / ((double) 1000000);
          publishProgress(i + ": " + results[i] + "ms");
        }
        publishProgress("-----          done           -----");
        return results;
      }

      Signature s = signer.signMessage("aMessage");
      publishProgress("done");

      publishProgress("Verifying... ");
      verifier = scheme.getVerifier();
      BigInteger bsn = signer.getLinkingBase();
      if (operation.equals("Verify")) {
        for (int i = 0; i < num_iter && !isCancelled(); i++) {
          System.gc();
          long begin = System.nanoTime();
          boolean status = verifier.isSignatureValid("aMessage", bsn, s);
          long end = System.nanoTime();
          if (!status)
            publishProgress("Verify failed!");
          results[i] = (end - begin) / ((double) 1000000);
          publishProgress(i + ": " + results[i] + "ms");
        }
        publishProgress("-----          done           -----");
        return results;
      }

      publishProgress("If you see this message, " +
      		            "no operation was measured (huh?)");
    } catch (SchemeException ex) {
      publishProgress("Error: " + ex.getMessage());
    }

    return null;
  }

}
