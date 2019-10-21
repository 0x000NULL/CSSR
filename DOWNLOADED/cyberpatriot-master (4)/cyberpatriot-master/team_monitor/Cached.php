<?php

function cached_file_get_contents($target_uri, $target_cached_filepath) {

  $data = file_get_contents($target_uri);
  if (false === $data || (strcmp($data,"") == 0)) {
    // attempt to use cached content
    $data = file_get_contents($target_cached_filepath) or die("<html><body>URI not available and no local cached copy.</body></html>");
  } else {
    $cfile = fopen($target_cached_filepath, 'w');
    if (FALSE === $cfile) {
      fwrite(STDERR, "Unable to update cache file: ${target_cached_filepath}\n");
    } else {
      // update CACHE
      fwrite($cfile, $data);
      fclose($cfile);
    } # unable to open cache, else
  } # get contents failed, else

  return $data;
}

?>
