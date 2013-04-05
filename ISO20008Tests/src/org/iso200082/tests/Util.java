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

public class Util
{

  public static double computeMean(double[] results)
  {
    double mean = 0;
    for (double single : results) {
      mean += single;
    }
    return mean / results.length;
  }
  
  public static void printMean(double mean)
  {
    System.out.println("Mean:   " + String.format("%2.2f", mean) + "ms");
  }
  
  public static double computeStdDev(double[] results, double mean)
  {
    double stddev = 0;
    for (double single : results)
      stddev += (mean - single) * (mean - single);
    stddev = Math.sqrt(stddev / results.length);
    
    return stddev;
  }
  
  public static void printStdDev(double stddev)
  {
    System.out.println("StdDev: " + String.format("%2.2f", stddev) + "ms");
  }

  public static void printMeanStdDev(double[] results)
  {
    double mean = computeMean(results);
    printMean(mean/1000000);
    printStdDev(computeStdDev(results, mean)/1000000);
  }
}
