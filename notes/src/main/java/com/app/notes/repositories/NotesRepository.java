package com.app.notes.repositories;
import com.app.notes.models.Note;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface NotesRepository extends JpaRepository<Note,Long> {
    List<Note> findByOwnerUsername(String OwnerUsername);
}
