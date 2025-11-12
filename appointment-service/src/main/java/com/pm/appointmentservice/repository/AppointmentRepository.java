package com.pm.appointmentservice.repository;

import com.pm.appointmentservice.entity.Appointment;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

public interface AppointmentRepository extends JpaRepository<Appointment, UUID> {
    List<Appointment> findByStartTimeBetween(LocalDateTime from, LocalDateTime to);
}
