<?php
session_start();

class AuthController extends Controller
{

	public $error = NULL;
	public $msg = NULL;
	
	public function index($name = '')
	{
		echo "welcome to Auth";
	}

	public function signup()
	{
		//validate
		$username = NULL;
		$email = NULL;
		$password = NULL;
		$confirm_password = NULL;

		if( !isset($_POST['susername']) || !isset($_POST['semail']) || !isset($_POST['spassword']) || !isset($_POST['sconfirmpassword']))
		{
			echo "not set";
			return $this->view('auth/login_signup', ['error'=>$this->error, 'msg'=>$this->msg]);
		}
		$username  = $_POST['susername'];
		$email = $_POST['semail'];
		$password = $_POST['spassword'];
		$confirm_password = $_POST['sconfirmpassword'];
		if ($confirm_password != $password)
		{
			//return with password not match
			$this->error['password_msimatch'] = true;
			return $this->view('auth/login_signup', ['error'=>$this->error, 'msg'=>$this->msg]);
		}
		echo $username;
		if (User::where('email', $email)->count() > 0)
		{
			//return user already signed up
			$this->error['email_exists'] = true;
			return $this->view('auth/login_signup', ['error'=>$this->error, 'msg'=>$this->msg]);
		}

		// $user = User::addUser($username, $email, md5($password));
		$user = new User;
		$user->setUserName($username);
		$user->setEmail($email);
		$user->setPassword($password);
		$user = $user->addUser();
		var_dump($user);
		if ($user != NULL)
		{
			//create user account and return to home
			$this->msg['status'] = "welcome";
			echo $user->getEmail() . " " . $user->getPassword();
			if(User::loginUser($user->getEmail(), $user->getPassword()))
			{
				//go to home
				return $this->view('display/vault', ['error'=>$this->error, 'msg'=>$this->msg]);
			}
		}

	}

	public function signin()
	{
		if( isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] !== "POST")
		{
			return $this->view('auth/login_signup', ['error'=>$this->error, 'msg'=>$this->msg]);
		} else if( !isset($_POST['email']) || !isset($_POST['password']))
		{
			
			return $this->setHeader('auth/signin');
		}
		$email = $_POST['email'];
		$password = $_POST['password'];

		if(User::loginUser($email, md5($password), $this->msg))
		{
			//go to home
			$this->setHeader('display/vault');
		} else {
			//return to view with error
		}
	}

	public function settings()
	{
		//display settings
	}
}