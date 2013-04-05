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

import org.iso200082.android.R;

import java.util.ArrayList;
import java.util.List;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.graphics.Typeface;
import android.os.AsyncTask;
import android.os.AsyncTask.Status;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.view.MotionEvent;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

/**
 * Simple Signature Scheme UI. Allows choosing the mechanism, key length, number
 * of iterations and operation/process to assess. The fixed length checkbox
 * forces the scheme to use a fixed group instead of generating one (to speed
 * things up..)
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
@SuppressLint("DefaultLocale")
public class MainActivity extends Activity implements OnItemSelectedListener {
  
  /** status label */
  private TextView             status_view = null;
  
  /** the {@link AsyncTask} that does the actual work */
  private MeasuringTask        task;
  
  /**
   * data backend for the key length spinner (to be updated on mechanism
   * changes)
   */
  private ArrayAdapter<String> len_adapter;
    
  @Override
  protected void onCreate(Bundle savedInstanceState)
  {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.main_activity);
    
    System.setProperty("sig-scheme-impl",
                       "org.iso200082.common.ISO20008Factory");
    
    status_view = (TextView) findViewById(R.id.tv_status);
    status_view.setMovementMethod(ScrollingMovementMethod.getInstance());
    status_view.setTypeface(Typeface.MONOSPACE);
    status_view.setOnTouchListener(new View.OnTouchListener() {
		
		@Override
		public boolean onTouch(View v, MotionEvent event) {
			v.getParent().requestDisallowInterceptTouchEvent(true);
			return false;
		}
	});

    List<String> spinner_data = new ArrayList<String>();
    len_adapter = new ArrayAdapter<String>(this,
                      android.R.layout.simple_spinner_dropdown_item,
                      spinner_data);
    Spinner len_spinner = (Spinner) findViewById(R.id.spinner_keylen);
    len_spinner.setAdapter(len_adapter);
    updateUI();
    
    Spinner mech_spinner = (Spinner) findViewById(R.id.sp_mechanism);
    mech_spinner.setOnItemSelectedListener(this);
    
    // heap grow test byte[]s
	// byte[] b = new byte[56*1024*1024];
	// byte[] b2 = new byte[64*1024*1024];
  }
  
  public void clickHandler(View v)
  {
    
    switch (v.getId()) {
      
      case R.id.btn_go:
        
        Button go_button = (Button) findViewById(R.id.btn_go);
        if (task != null && task.getStatus() == Status.RUNNING)
        {
          task.cancel(true);
          go_button.setEnabled(false);
        } else {
          Spinner mech_spinner = (Spinner) findViewById(R.id.sp_mechanism);
          Spinner op_spinner   = (Spinner) findViewById(R.id.sp_op);
          
          String mechanism = mech_spinner.getSelectedItem().toString();
          String operation = op_spinner.getSelectedItem().toString();
          
          TextView status_textview = (TextView) findViewById(R.id.tv_status);
          TextView mean_view       = (TextView) findViewById(R.id.tv_mean);
          TextView stddev_view     = (TextView) findViewById(R.id.tv_stddev);
          TextView min_view        = (TextView) findViewById(R.id.tv_min);
          TextView max_view        = (TextView) findViewById(R.id.tv_max);
          CheckBox do_create       = (CheckBox) findViewById(R.id.cb_setup);
          RadioGroup impl          = (RadioGroup) findViewById(R.id.rb_prim);
          RadioGroup mult          = (RadioGroup) findViewById(R.id.rb_mult);
          RadioGroup precomp       = (RadioGroup) findViewById(R.id.rb_precomp);
          
          status_textview.setText("");
          mean_view.setText(R.string.meanlabel);
          stddev_view.setText(R.string.stddevlabel);
          min_view.setText(R.string.minlabel);
          max_view.setText(R.string.maxlabel);
          
          task = new MeasuringTask(this, status_textview);
          Spinner len_spinner     = (Spinner) findViewById(R.id.spinner_keylen);
          EditText iter_textfield = (EditText)findViewById(R.id.et_iter);
          String keylen     = len_spinner.getSelectedItem().toString();
          String iterations = iter_textfield.getText().toString();
          try {
            int i = Integer.parseInt(iterations);
            if (i > 1000 || i < 1) {
              Toast.makeText(getApplicationContext(),
                  "Max iterations = 1000, min = 1", Toast.LENGTH_SHORT).show();
              return;
            }
            
          } catch (Exception e) {
            Toast.makeText(getApplicationContext(),
                "Iterations has to be numeric", Toast.LENGTH_SHORT).show();
            return;
          }
          go_button.setText(R.string.abort);
          
          String ci = ((RadioButton) findViewById(
                        impl.getCheckedRadioButtonId()))
                      .getText().toString().toLowerCase();
          String mi = ((RadioButton) findViewById(
                        mult.getCheckedRadioButtonId()))
                      .getText().toString().toLowerCase();
          
          String monty = String.valueOf(((CheckBox) findViewById(R.id.cb_monty))
                               .isChecked());
          String sprecomp = "0";
          switch(precomp.getCheckedRadioButtonId()) 
          {
            case R.id.rb_precomp1: sprecomp = "1"; break;
            case R.id.rb_precomp2: sprecomp = "2"; break;
            default: sprecomp = "0"; break;
          }
          System.gc();
          task.execute(mechanism, operation, iterations, keylen,
              String.valueOf(do_create.isChecked()), ci, sprecomp, monty, mi);
        }
        break;
      default:
        break;
    }
  }
  
  /**
   * Called from {@link MeasuringTask} when all results were collected.
   * Computes the stats
   * 
   * @param results The list of measured timings
   */
  public void handResults(double[] results)
  {
    if (results != null)
      showStats(results);
    else
      status_view.setText(status_view.getText() + "\n"
          + "Received invalid results");
    
    Button go_button = (Button) findViewById(R.id.btn_go);
    go_button.setText(R.string.go);
    task = null;
  }
  
  /**
   * Updates the status field to indicate abortion
   */
  public void notifyCancellation()
  {
    status_view.setText(status_view.getText() + "\n"
        + "-------          aborted           -------");
    Button go_button = (Button) findViewById(R.id.btn_go);
    go_button.setText(R.string.go);
    go_button.setEnabled(true);
  }
  
  // actual stats computation
  private void showStats(double[] results) 
  {
    double mean = 0, min = Double.MAX_VALUE, max = 0;
    for (int i = 0; i < results.length; i++) {
      mean += results[i];
      if (results[i] > max)
        max = results[i];
      if (results[i] < min)
        min = results[i];
    }
    mean = mean / results.length;
    
    double stddev = 0;
    for (int i = 0; i < results.length; i++)
      stddev += (mean - results[i]) * (mean - results[i]);
    stddev = Math.sqrt(stddev / results.length);
    
    TextView mean_view   = (TextView) findViewById(R.id.tv_mean);
    TextView stddev_view = (TextView) findViewById(R.id.tv_stddev);
    TextView min_view    = (TextView) findViewById(R.id.tv_min);
    TextView max_view    = (TextView) findViewById(R.id.tv_max);
    
    mean_view.setText("Mean: " + String.format("%2.2f", mean));
    stddev_view.setText("Std. Dev.: " + String.format("%2.2f", stddev));
    min_view.setText("Min: " + String.format("%2.2f", min));
    max_view.setText("Max: " + String.format("%2.2f", max));
  }
  
  private void updateUI()
  {
    Spinner mech_spinner = (Spinner) findViewById(R.id.sp_mechanism);
    String  selection    = mech_spinner.getSelectedItem().toString();
    RadioButton precomp2 = (RadioButton) findViewById(R.id.rb_precomp2);
    RadioGroup impl      = (RadioGroup) findViewById(R.id.rb_prim);
    RadioGroup mult      = (RadioGroup) findViewById(R.id.rb_mult);
    CheckBox   monty     = (CheckBox) findViewById(R.id.cb_monty);
    
    len_adapter.clear();
    if (selection.equals("Mechanism 1"))
    {
      len_adapter.add(String.valueOf(512));
      len_adapter.add(String.valueOf(1024));
      setButtonsEnabled(false, impl);
      setButtonsEnabled(false, mult);
      precomp2.setEnabled(true);
      monty.setEnabled(false);
      monty.setChecked(false);
    } 
    else if (selection.equals("Mechanism 5"))
    {
      len_adapter.add(String.valueOf(1024));
      len_adapter.add(String.valueOf(2048));
      setButtonsEnabled(true, impl);
      setButtonsEnabled(true, mult);
      precomp2.setEnabled(false);
      precomp2.setChecked(false);
      monty.setEnabled(false);
    } 
    else
    {
      len_adapter.add(String.valueOf(256));
      setButtonsEnabled(true, impl);
      setButtonsEnabled(true, mult);
      precomp2.setEnabled(true);
      monty.setEnabled(true);
    }
    
    len_adapter.notifyDataSetChanged();
  }
  
  private void setButtonsEnabled(boolean enabled, RadioGroup group)
  {
    for(int i = 0; i < group.getChildCount(); i++)
      ((RadioButton) group.getChildAt(i)).setEnabled(enabled);
  }
  
  @Override
  public void onItemSelected(AdapterView<?> arg0, 
                             View arg1, int arg2, long arg3) {
    updateUI();
  }
  
  @Override
  public void onNothingSelected(AdapterView<?> arg0) {
    // nothing.
  }
}
