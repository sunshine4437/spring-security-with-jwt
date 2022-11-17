package com.example;

public class Sub {
    private static int num = 0;

    public static String test() {
        System.out.println("정적 팩토리 메소드 생성" + num++);
        return "asd";
    }
}
