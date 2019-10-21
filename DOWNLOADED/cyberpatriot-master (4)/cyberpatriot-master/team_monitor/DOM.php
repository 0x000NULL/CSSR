<?php

function dom_deleteNode($node) {
  dom_deleteChildren($node);
  $parent = $node->parentNode;
  if ($parent != null && isset($parent->firstChild)) {
    $oldnode = $parent->removeChild($node);
  }
}

function dom_deleteChildren($node) {
  while (isset($node->firstChild)) {
    dom_deleteChildren($node->firstChild);
    $node->removeChild($node->firstChild);
  } # while has children
}

function dom_prependChild($new_parent, $new_child) {
  if (isset($new_parent->firstChild)) {
    $new_parent->insertBefore($new_child, $new_parent->firstChild);
  } else {
    $new_parent->appendChild($new_child);
  } # if has children, else
}

?>
