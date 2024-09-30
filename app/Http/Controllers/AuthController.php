<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $data = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed'
        ]);
        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => bcrypt($data['password'])
        ]);

        $token = $user->createToken('main')->plainTextToken;
        return response()->json([
            'user' => $user,
            'token' => $token
        ]);
    }
    public function login(Request $request){
        $data = $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string'
        ]);
        if(!auth()->attempt($data)){
            return response()->json([
                'message' => 'Invalid Credentials'
            ]);
        }
        $token = auth()->user()->createToken('main')->plainTextToken;
        return response()->json([
            'user' => auth()->user(),
            'token' => $token
        ]);
    }
    public function loginAuto(Request $request)
    {
        $data = $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string'
        ]);
        $user = User::where('email', $data['email'])->first();
        if ($user) {
            if (password_verify($data['password'], $user->password)) {
                $token = $user->createToken('main')->plainTextToken;
                return response()->json([
                    'user' => $user,
                    'token' => $token
                ]);
            }
        }
        return response()->json([
            'message' => 'Invalid email or password'
        ]);
    }
    public function logout(Request $request)
    {
//        $user->tokens()->where('id', $user->currentAccessToken()->id)->delete();
        $request->user()->currentAccessToken()->delete();
        return response()->json([
            'message' => 'Logged out',
            'user' => null,
            'token' => null
        ]);
    }
    public function getToken(Request $request) {
        // dd('$user');
        return $request->user()->currentAccessToken();
        $user = User::where('email', $request->email)->first();
        dd($user->currentAccessToken());
    }
}
