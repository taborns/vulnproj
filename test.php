<?php 
    echo $_GET;

    
    class A {
        public static $a = 12;
        public $g = 16;
        public static final function testMe() {}
        
        private $c = 16;
    }

    $data = new A();
    $data->testMe();
?>