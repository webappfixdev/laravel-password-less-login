<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Providers\RouteServiceProvider;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use App\Models\User;
use App\Notifications\SendPasswordLessLinkNotification;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = RouteServiceProvider::HOME;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }

    public function login(Request $request)
    {
        if($request->input('submit') == 'password-less'){
            $user = $this->loginViaPasswordLessLink($request);

            if (! $user) {
                return redirect()->route('login')
                ->withErrors(['email' => 'User With this email dose not exist.'])
                ->withInput();
            }

            return redirect()->route('login')
                ->withMessage('Password Less Links Sent To The Registration Email Address.');
        }

        $this->validateLogin($request);

        if (method_exists($this,'hasTooManyLoginAttempts') && 
            $this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);

            return $this->sendLockoutResponse($request);
        }

        if ($this->attemptLogin($request)) {
            if ($request->hasSession()) {
                $request->session()->put('auth.password_confirmation_at',time());
            }
            return $this->sendLoginResponse($request);
        }

        $this->incrementLoginAttempts($request);

        return $this->sendFailedLoginResponse($request);
    }

    public function loginViaPasswordLessLink(Request $request)
    {
       $user = User::where('email',$request->get('email'))->first();

       if ($user) {
           $user->notify(new SendPasswordLessLinkNotification());
       }
       return $user;
    }
}
