package com.amigoscode.controller;

import com.amigoscode.model.Student;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private final static List<Student> students = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Maria Johns"),
            new Student(3, "Anna Smith")
    );

    @GetMapping(path = "/{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId){
        return students.stream()
                .filter(student -> student.getStudentId().equals(studentId))
                .findFirst().orElseThrow(()-> new IllegalStateException("Student " + studentId + "does not exist"));
    }
}
