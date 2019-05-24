<?php 

    class A{
    
        public function __construct($data) {
            echo $data;
        }
    }

    $a = new A($_GET['tabor']);
