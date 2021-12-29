package com.wagner.springsecurityamigos.security;

import com.google.common.collect.Sets;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Set;
import static com.wagner.springsecurityamigos.security.ApplicationUserPermission.*;

@AllArgsConstructor
@Getter
public enum ApplicationUserRole {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)),
    ADMINTRAINEE(Sets.newHashSet(COURSE_READ, STUDENT_READ));




    private final Set<ApplicationUserPermission> permissions;

}
