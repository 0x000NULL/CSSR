<?php
require 'CPX.php';    # static extract from CPX rules PDF

require 'DOM.php';    # HTML DOM manipulation helper utilities
require 'Cached.php'; # simplistic write-thru caching utilities


$BURL    = 'http://scoreboard.uscyberpatriot.org';
$TURL    = "${BURL}/index.php";
$CACHE   = 'http_scoreboard_uscyberpatriot_org_index_php.cached';
#$ARCHIVE = 'score_archive/cpx_round_1/';
#$ARCHIVE = 'score_archive/cpx_round_2/';
$ARCHIVE = 'score_archive/cpx_round_3/';
# CPIX Round 3 Live (scoreboard) and Official (state) data
#$CACHE = 'score_archive/cpix_round_3/http_scoreboard_uscyberpatriot_org_index_php.cached';
#$CACHE = 'score_archive/cpix_round_3/cpix_state__middle_school_division.cached';
#$CACHE = 'score_archive/cpix_round_3/cpix_state__all_service_division.cached';
#$CACHE = 'score_archive/cpix_round_3/cpix_state__open_division.cached';
#$CACHE = 'score_archive/cpix_round_3/cpix_state__all_divisions.cached';

if (  BURL  === ""
   || TURL  === ""
   || CACHE === "") {
  die("<html><body>Invalid URL to fetch.</body></html>");
} # if URL/CACHE is invalid


// DEFAULT defines no selectors
$DEBUG = 0;
$requested_team_divisions = array();
$requested_team_locations = array();
$requested_no_team_locations = array();
$requested_team_tiers = array();
$requested_team_ids = array();
$requested_no_team_ids = array();


// INPUT: Set filter selectors
/**
 * Selectors can be set manually as follows or will be parsed
 * from query argument list if present.
 *
$requested_team_divisions = array( 'Open' );
$requested_team_locations = array( 'CA' );
 */


$query = array();
parse_str($_SERVER['QUERY_STRING'], $query);
if ($DEBUG) {
  echo "query:\n";
  print_r($query);
} # if debug enabled
foreach ( array_keys($query) as $query_key ) {

  switch ($query_key) {

    case 'team':
    case 'teams':
      if ($DEBUG) {
        echo "query{teams}    = $query[$query_key]\n";
      } # if debug enabled
      $tmp_requested_team_ids = explode(',', $query[$query_key]);
      if ($DEBUG) {
        foreach ( $tmp_requested_team_ids as $team_id ) {
          echo "query{teams}[*] = ${team_id}\n";
        } # foreach requested team id
      } # if debug enabled
      switch ($query_key) {
        case 'team':
          $requested_team_ids[] = $tmp_requested_team_ids[0];
          break;
        case 'teams':
          $requested_team_ids = array_merge($requested_team_ids, $tmp_requested_team_ids);
          break;
      } # handle singular and plural cases
      break;

    case 'no_team':
    case 'no_teams':
      if ($DEBUG) {
        echo "query{no_teams}    = $query[$query_key]\n";
      } # if debug enabled
      $tmp_requested_no_team_ids = explode(',', $query[$query_key]);
      if ($DEBUG) {
        foreach ( $tmp_requested_no_team_ids as $team_id ) {
          echo "query{no_teams}[*] = ${team_id}\n";
        } # foreach requested team id
      } # if debug enabled
      switch ($query_key) {
        case 'no_team':
          $requested_no_team_ids[] = $tmp_requested_no_team_ids[0];
          break;
        case 'no_teams':
          $requested_no_team_ids = array_merge($requested_no_team_ids, $tmp_requested_no_team_ids);
          break;
      } # handle singular and plural cases
      break;

    case 'tier':
    case 'tiers':
      if ($DEBUG) {
        echo "query{tiers}    = $query[$query_key]\n";
      } # if debug enabled
      $tmp_requested_team_tiers = explode(',', $query[$query_key]);
      if ($DEBUG) {
        foreach ( $tmp_requested_team_tiers as $team_tier ) {
          echo "query{tiers}[*] = ${team_tier}\n";
        } # foreach requested team tier
      } # if debug enabled
      switch ($query_key) {
        case 'tier':
          $requested_team_tiers[] = $tmp_requested_team_tiers[0];
          break;
        case 'tiers':
          $requested_team_tiers = array_merge($requested_team_tiers, $tmp_requested_team_tiers);
          break;
      } # handle singular and plural cases
      break;

    case 'location':
    case 'locations':
      if ($DEBUG) {
        echo "query{locations}    = $query[$query_key]\n";
      } # if debug enabled
      $tmp_requested_team_locations = explode(',', $query[$query_key]);
      if ($DEBUG) {
        foreach ( $tmp_requested_team_locations as $team_location ) {
          echo "query{locations}[*] = ${team_location}\n";
        } # foreach requested team location
      } # if debug enabled
      switch ($query_key) {
        case 'location':
          $requested_team_locations[] = $tmp_requested_team_locations[0];
          break;
        case 'locations':
          $requested_team_locations = array_merge($requested_team_locations, $tmp_requested_team_locations);
          break;
      } # handle singular and plural cases
      break;

    case 'no_location':
    case 'no_locations':
      if ($DEBUG) {
        echo "query{no_locations}    = $query[$query_key]\n";
      } # if debug enabled
      $tmp_requested_no_team_locations = explode(',', $query[$query_key]);
      if ($DEBUG) {
        foreach ( $tmp_requested_no_team_locations as $team_location ) {
          echo "query{no_locations}[*] = ${team_location}\n";
        } # foreach requested team location
      } # if debug enabled
      switch ($query_key) {
        case 'no_location':
          $requested_no_team_locations[] = $tmp_requested_no_team_locations[0];
          break;
        case 'no_locations':
          $requested_no_team_locations = array_merge($requested_no_team_locations, $tmp_requested_no_team_locations);
          break;
      } # handle singular and plural cases
      break;

    case 'division':
    case 'divisions':
      if ($DEBUG) {
        echo "query{divisions}    = $query[$query_key]\n";
      } # if debug enabled
      $tmp_requested_team_divisions = explode(',', $query[$query_key]);
      if ($DEBUG) {
        foreach ( $tmp_requested_team_divisions as $team_division ) {
          echo "query{divisions}[*] = ${team_division}\n";
        } # foreach requested team division
      } # if debug enabled
      switch ($query_key) {
        case 'division':
          $requested_team_divisions[] = $tmp_requested_team_divisions[0];
          break;
        case 'divisions':
          $requested_team_divisions = array_merge($requested_team_divisions, $tmp_requested_team_divisions);
          break;
      } # handle singular and plural cases
      break;

    case 'debug':
      if ($DEBUG) {
        echo "query{debug}    = $query[$query_key]\n";
      } # if debug enabled
      if (strcmp($query[$query_key],'1') == 0) {
        $DEBUG=1;
        if ($DEBUG) {
          echo "query{debug}[*] = $query[$query_key]\n";
        } # if debug enabled
      } else {
        if ($DEBUG != 1) {
          $DEBUG=0;
        } # if debug not enabled
        if ($DEBUG) {
          echo "query{debug}[*] = $query[$query_key]\n";
        } # if debug enabled
      } # if enable debug, else
      break;

  } # match recognized query parameters
} # foreach query parameter


if ($DEBUG) {
  echo "<pre>";
} # if debug enabled


// INPUT: output selectors
//   TODO: code support for output selectors


// validate request arguments (divisions, locations, tiers, team IDs)
$monitored_team_divisions = array();
$monitored_team_locations = array();
$filtered_team_locations = array();
$monitored_team_tiers = array();
$monitored_team_ids = array_unique($requested_team_ids);
$filtered_team_ids = array_unique($requested_no_team_ids);

foreach ( array_unique($requested_team_divisions) as $requested_division ) {
  if (in_array($requested_division, CPX::$divisions)) {
    $monitored_team_divisions[] = $requested_division;

    if ($DEBUG) {
      echo "Adding division $requested_division\n";
    } # if debug enabled
  } else {
    echo "ERROR: Ignoring request to monitor unsupported division ${requested_division}\n";
  } # requested division supported, else
} # foreach requested division

// harvest locations from each region
$all_locations = array();
foreach ( array_keys(CPX::$locations_by_region) as $region ) {
  foreach ( CPX::$locations_by_region[$region] as $location ) {
    $all_locations[] = $location;
  } # foreach location in region
} # foreach region
$all_locations = array_unique($all_locations);
foreach ( array_unique($requested_team_locations) as $requested_location ) {
  if (in_array($requested_location, $all_locations)) {
    $monitored_team_locations[] = $requested_location;

    if ($DEBUG) {
      echo "Adding location $requested_location\n";
    } # if debug enabled
  } else {
    echo "ERROR: Ignoring request to monitor unsupported location ${requested_location}\n";
  } # requested location supported, else
} # foreach requested location
foreach ( array_unique($requested_no_team_locations) as $requested_location ) {
  if (in_array($requested_location, $all_locations)) {
    $filtered_team_locations[] = $requested_location;

    if ($DEBUG) {
      echo "Filtering location $requested_location\n";
    } # if debug enabled
  } else {
    echo "ERROR: Ignoring request to filter unsupported location ${requested_location}\n";
  } # requested location supported, else
} # foreach requested location

foreach ( array_unique($requested_team_tiers) as $requested_tier ) {
  if (in_array($requested_tier, CPX::$tiers)) {
    $monitored_team_tiers[] = $requested_tier;

    if ($DEBUG) {
      echo "Adding tier $requested_tier\n";
    } # if debug enabled
  } else {
    echo "ERROR: Ignoring request to monitor unsupported tier ${requested_tier}\n";
  } # requested tier supported, else
} # foreach requested tier


// final input validation
if (  ($monitored_team_ids === null || $monitored_team_ids->length > 0)
   && ($monitored_team_tiers === null || $monitored_team_tiers->length > 0)
   && ($monitored_team_locations === null || $monitored_team_locations->length > 0)
   && ($monitored_team_divisions === null || $monitored_team_divisions->length > 0) ) {
  die("<html><body>No monitor inputs provided.</body></html>");
} # if not monitoring teams by id/tier/location/division


// track ranking order over:
//   - global
//   - division
//   - division/tier
//   - division/location/tier
$global_order = 0;

$division_order = array();
$division_tier_order = array();
$division_location_tier_order = array();

foreach ( CPX::$divisions as $division ) {
  $division_order[$division] = 0;

  if ($DEBUG) {
    echo "\$division_order[$division] = 0\n";
  } # if debug enabled

  foreach ( CPX::$tiers as $tier ) {
    $division_tier_order[$division][$tier] = 0;

    if ($DEBUG) {
      echo "\$division_tier_order[$division][$tier] = 0\n";
    } # if debug enabled
  } # foreach official tier

  // use region to lookup location
  foreach ( array_keys(CPX::$locations_by_region) as $region ) {
    foreach ( CPX::$locations_by_region[$region] as $location ) {
      foreach ( CPX::$tiers as $tier ) {
        $division_location_tier_order[$division][$location][$tier] = 0;

        if ($DEBUG) {
          echo "\$division_location_tier_order[$division][$location][$tier] = 0\n";
        } # if debug enabled
      } # foreach official tier
    } # foreach location

  } # if All Service division, else

} # foreach official division



// fetch external URL content
$data = cached_file_get_contents($TURL, $CACHE);

// archive cachefile for later viewing
$archived_cachefile = 
      $ARCHIVE
    . $CACHE
    . trim(shell_exec('LANG="en_US.UTF8" date +"-%Y_%m_%d-%H_%M_%S"'))
    . '.tar.bz2';
$archive_directory = dirname( $archived_cachefile );
shell_exec("[ -f '$CACHE' ] \
    && mkdir -p '$archive_directory' \
    && tar cjf '$archived_cachefile' '$CACHE'");


$rank = 0;
$scores = array();


// parse scoreboard as the first table
$dom = new domDocument;
@$dom->loadHTML($data);
$dom->preserveWhiteSpace = FALSE;
$elements_to_remove = array();
$finder = new DomXPath($dom);


##
## Process/update <head> section
##

$head = $dom->getElementsByTagName('head');
if (1 == $head->length) {
  $head = $head->item(0);

  // remove existing base definition
  $base = $head->getElementsByTagName('base');
  foreach ( $base as $base_element ) {
    $elements_to_remove[] = $base_element;

  } # foreach base element

  // add customized base URL
  $custom_base = $dom->createElement('base');
  $custom_base_href = $dom->createAttribute('href');
  $custom_base_href->value = "${BURL}";
  $custom_base->appendChild($custom_base_href);
  dom_prependChild($head, $custom_base);

  // add in-line styling with CSS
  $inline_style = $dom->createElement('style', '                             
.CSSTableGenerator tr:nth-child(odd) { background-color:#f7f7f7; }
.CSSTableGenerator tr:nth-child(even) { background-color:#d7d7d7; }');
  $inline_style_type = $dom->createAttribute('type');
  $inline_style_type->value = "text/css";
  $inline_style->appendChild($inline_style_type);
  $head->appendChild($inline_style);

} # page has head section


##
## Process/update scoreboard table
##

// identify table elements for removal
$tabs = $dom->getElementsByTagName('table');
if (0 != $tabs->length) {
  $scoreboard = $tabs->item(0);
  foreach ( $scoreboard->getElementsByTagName('tr') as $row ) {
    $cols = $row->getElementsByTagName('td');

    $team_id = '';
    $location = '';
    $division = '';
    $tier = '';
    $num_images = '';
    $time = '';
    $ccs_score = '';
    $warning = '';

    //[Team#|Location|Division|Tier|#Images|Time (H:MM)|Score|Warning]
    $team_id = trim($cols[0]->nodeValue);
    $location = trim($cols[1]->nodeValue);
    $division = trim($cols[2]->nodeValue);
    $tier = trim($cols[3]->nodeValue);
    //$num_images = trim($cols[4]->nodeValue);
    $time = trim($cols[5]->nodeValue);
    $ccs_score = trim($cols[6]->nodeValue);
    $warning = trim($cols[7]->nodeValue);

    // manage table header
    if ($team_id == "TeamNumber") {
      // extend table with ranking by division within tier and location

      // for Round 3 or 4 (live scoreboard, with tier)
      //[Team#|Location|Division|Tier|#Images|Time (H:MM)|Score|Warning]
      // -no edits!

      /**
      // for Round 3 (official Open/All Service/Middle School) scores
      // -relabel columns 5, 6, 7, and 8 as Cisco, CCS, Total Score, and Advancing?
      // -remove column 3
      $cols[1]->nodeValue = 'Location';
      $cols[5]->nodeValue = 'Cisco';
      $cols[6]->nodeValue = 'CCS';
      $cols[7]->nodeValue = 'Total Score';
      $cols[8]->nodeValue = 'Advancing?';
      $elements_to_remove[] = $cols[3];
      */

      $division_tier_rank_table_data = $dom->createElement('td', 'D:T Rank');
      $dt_rank_title = $dom->createAttribute('title');
      $dt_rank_title->value = 'Rank within Division and Tier';
      $division_tier_rank_table_data->appendChild($dt_rank_title);
      $row->appendChild($division_tier_rank_table_data);

      $division_location_tier_rank_table_data = $dom->createElement('td', 'D:L:T Rank');
      $dlt_rank_title = $dom->createAttribute('title');
      $dlt_rank_title->value = 'Rank within Division, Location, and Tier';
      $division_location_tier_rank_table_data->appendChild($dlt_rank_title);
      $row->appendChild($division_location_tier_rank_table_data);

      continue;
    } # short-circuit table header handling

    // for Round 3 or 4 (live scoreboard, with tier)
    //[Team#|Location|Division|Tier|#Images|Time (H:MM)|Score|Warning]
    // -no edits!

    /**
    // for Round 3 (official Open/All Service/Middle School) scores
    // -remap the tier<->location
    // -remove column 3
    $cols[1]->nodeValue = $location;
    $cols[4]->nodeValue = $tier;
    $elements_to_remove[] = $cols[3];
    */

    // Tier Rank Determination (process all records)
    //   - scores are given in rank order, track rank
    //     globally and within division, tier, and location
    //     as applicable
    $global_rank = 0;
    $division_rank = 0;
    $division_tier_rank = 0;
    $division_location_tier_rank = 'N/A';

    $global_rank = $global_order += 1;
    if (array_key_exists($division, $division_order)) {
      $division_rank = $division_order[$division] += 1;

      if (array_key_exists($tier, $division_tier_order[$division])) {
        $division_tier_rank = $division_tier_order[$division][$tier] += 1;
if ($DEBUG) {
  echo "division[$division], tier[$tier] rank = $division_tier_rank\n";
} # if debug enabled
      } # valid tier in division
else {
  if ($DEBUG) {
    echo "invalid division/tier: division[$division], tier[$tier], team_id=$team_id\n";
  }
}

      if (null != $division_location_tier_order[$division]) {
        if (array_key_exists($location, $division_location_tier_order[$division])) {
          if (array_key_exists($tier, $division_location_tier_order[$division][$location])) {
            $division_location_tier_rank = $division_location_tier_order[$division][$location][$tier] += 1;
          } # valid tier in division/location
        } # valid location in division

      } # division is valid for location lookup

    } # valid division
else {
if ($DEBUG) {
if ( !empty($monitored_team_ids) and in_array($team_id, $monitored_team_ids, TRUE) ) {
  echo "division ($division) is NOT valid for division lookup [ '${team_id}', '${tier}' ]\n";
} # if team is monitored
} # if debug enabled
}


    // apply monitoring filters, if any
    if ( ( !empty($monitored_team_ids) and !in_array($team_id, $monitored_team_ids, TRUE) ) or ( !empty($filtered_team_ids) and in_array($team_id, $filtered_team_ids, TRUE) ) ) {
      $elements_to_remove[] = $row;
if ($DEBUG) {
  echo "filtering out team (${team_id})\n";
} # if debug enabled
      continue;
    } # filtering based on team id

    if ( !empty($monitored_team_tiers) and !in_array($tier, $monitored_team_tiers, TRUE) ) {
      $elements_to_remove[] = $row;
if ($DEBUG) {
  echo "filtering out tier (${tier}) for team (${team_id})\n";
} # if debug enabled
      continue;
    } # filtering based on tier

    if ( ( !empty($monitored_team_locations) and !in_array($location, $monitored_team_locations, TRUE) ) or ( !empty($filtered_team_locations) and in_array($location, $filtered_team_locations, TRUE) ) ) {
      $elements_to_remove[] = $row;
if ($DEBUG) {
  echo "filtering out location (${location}) for team (${team_id})\n";
} # if debug enabled
      continue;
    } # filtering based on location

    if ( !empty($monitored_team_divisions) and !in_array($division, $monitored_team_divisions, TRUE) ) {
      $elements_to_remove[] = $row;
if ($DEBUG) {
  echo "filtering out division (${division}) for team (${team_id})\n";
} # if debug enabled
      continue;
    } # filtering based on division


    // extend table with ranks for:
    // - division:tier
    // - division:location:tier
    $division_tier_rank_table_data = $dom->createElement('td', "${division_tier_rank}");
    $row->appendChild($division_tier_rank_table_data);

    $division_location_tier_rank_table_data = $dom->createElement('td', "${division_location_tier_rank}");
    $row->appendChild($division_location_tier_rank_table_data);

    $scores[$team_id] = array("team_id"     => $team_id,
                              "tier"        => $tier,
                              "location"    => $location,
                              "division"    => $division,
                              "time"        => $time,
                              "ccs_score"   => $ccs_score,
                              "warning"     => $warning,

                              "global_rank" => $global_rank,
                              "dt_rank"     => $division_tier_rank,
                              "dlt_rank"    => $division_location_tier_rank);

  } # foreach scoreboard table row

} # scoreboard has table


##
## Schedule removal of elements, maximize display of team info
##

// mark class 'disclaimer' for removal
$disclaimer_cls = 'disclaimer';
$nodes = $finder->query("//*[contains(@class, '$disclaimer_cls')]");
foreach ( $nodes as $node ) {
  $elements_to_remove[] = $node;
} # foreach disclaimer class element to remove

// mark first main class element for removal
$main_cls = 'header';
$nodes = $finder->query("//*[contains(@class, '$main_cls')]");
foreach ( $nodes as $node ) {
  $elements_to_remove[] = $node;
  break;// only remove one element!
} # foreach header class node

// mark class 'navbar' for removal
$navbar_cls = 'navbar';
$nodes = $finder->query("//*[contains(@class, '$navbar_cls')]");
foreach ( $nodes as $node ) {
  $elements_to_remove[] = $node;
} # foreach navbar class element to remove

// mark h1 elements for removal
$h1 = $dom->getElementsByTagName('h1');
foreach ( $h1 as $node ) {
  $elements_to_remove[] = $node;
} # foreach h1 element to remove

// mark first h2 element for removal
$h2 = $dom->getElementsByTagName('h2');
if (0 != $h2->length) {
  $elements_to_remove[] = $h2->item(0);
} # mark first h2 element for removal

// mark img elements for removal
$img = $dom->getElementsByTagName('img');
foreach ( $img as $node ) {
  $elements_to_remove[] = $node;
} # foreach img element to remove

// mark paragraph elements for removal
$para = $dom->getElementsByTagName('p');
foreach ( $para as $node ) {
  $elements_to_remove[] = $node;
} # foreach paragraph element to remove



// process elements identified for removal
foreach ( $elements_to_remove as $element ) {
  dom_deleteNode($element);
} # foreach DOM element to remove



if ($DEBUG) {

  // team monitor summary debug
  foreach ( $scores as $monitored_team ) {
    # unpack team scores from associative array (map)
    extract($monitored_team);

    echo "<div>";

    $slash_tier = '';
    if ($tier != "") { $slash_tier="/${tier}"; }
    if (strcmp($division, CPX::$All_Service_Division_Name) === 0) {
      echo "team [$team_id] in ${division}${slash_tier} @ rank ${dt_rank}/${dlt_rank} (dt/dlt): $ccs_score in $location";
    } else {
      echo "team [$team_id] in ${division}${slash_tier} @ rank ${dt_rank}/${dlt_rank} (dt/dlt): $ccs_score in $location";
    } # if All Service division, else
    if ($warning != "") {
      echo " with $warning\n";
    } else {
      echo "\n";
    } # team has warnings, else

    echo "</div>";

  } # foreach monitored team (debug)

  // close debug output
  echo "</pre>";

} else {

  // emit post-processed HTML
  echo $dom->saveHTML();

} # if debug enabled

?>
