<?php
// static extract from CPX rules PDF
//  - divisions, tiers, regions->locations
class CPX {

  public static $All_Service_Division_Name = 'All Service';
  public static $Open_Division_Name = 'Open';
  public static $Middle_School_Division_Name = 'Middle School';
  public static $divisions = array(
      'Open', 'All Service', 'Middle School' );

  public static $tiers = array(
// CPX Round 1 & 2 used 'High School' and 'Middle School' teirs
//      'High School', 'Middle School' );
      'Platinum', 'Gold', 'Silver',
      'High School', 'Middle School' );

  public static $locations_by_region = array(
      'Northeast'    => array( 'CT', 'ME', 'MA', 'NH', 'NJ', 'NY', 'RI', 'VT' ),
      'Mid-Atlantic' => array( 'DE', 'KY', 'MD', 'OH', 'PA', 'VA', 'DC', 'WV' ),
      'Southeast'    => array( 'AL', 'FL', 'GA', 'LA', 'MS', 'NC', 'SC', 'TN' ),
      'Midwest'      => array( 'IL', 'IN', 'IA', 'MI', 'MN', 'NE', 'ND', 'SD', 'WI' ),
      'Southwest'    => array( 'AZ', 'AR', 'CO', 'KS', 'MO', 'NM', 'OK', 'TX' ),
      'West'         => array( 'CA', 'MT', 'ID', 'NV', 'OR', 'UT', 'WA', 'WY' ),

      # Known Abbreviations
      #  AK  = Alaska
      #  AE  = Armed Forces, Europe
      #  AP  = Armed Forces, Pacific
      #  AS  = American Samoa
      #  CAN = Canada (not used for CPIX?)
      #  GU  = Guam
      #  HI  = Hawaii
      #  PR  = Puerto Rico
      #  VI  = Virgin Islands
      #  VIR = US Virgin Islands (not used for CPIX?)
      #
      # Guessed Abbreviations (CPIX)
      #  GER = Germany (assumed as DE is ambiguous with Delaware, not used for CPIX?)
      #
      # Unexpected Abbreviations (CPIX)
      #  AB = Alberta, Canada
      #  AU = Australia?
      #  HU = Hungary?
      #  MB = Manitoba, Canada
      #  NB = New Brunswick, Canada
      #  ON = Ontario, Canada
      #  SG = Singapore?
      #
      # Unexpected Abbreviations (CPX)
      #  AUS = Australia
      #  ARE = Australia
      #  DEU = Germany
      #
      'At-Large'     => array( 'AK', 'AE', 'AP', 'AS', 'CAN', 'GU', 'HI', 'PR', 'VI', 'VIR', 'AB', 'AU', 'HU', 'MB', 'NB', 'ON', 'SG', 'AUS', 'ARE', 'DEU' ) ); 

  public static $organization_type_as_category = array(
      'Air Force JROTC', 'Army JROTC', 'Civil Air Patrol',
      'Marine Corps JROTC', 'Naval Sea Cadet Corps', 'Navy JROTC' );
}
?>
