package com.app.notes.controller;

import com.app.notes.models.Note;
import com.app.notes.services.NoteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
@CrossOrigin(value = "")
public class NotesController {
    @Autowired
    private NoteService noteService;
    @Value("${frontend.url}")
    String frontendUrl;
    @PostMapping("/notes")
    public Note createNote(@RequestBody String content, @AuthenticationPrincipal
    UserDetails userDetails)
    {
        String username = userDetails.getUsername();
        return noteService.createNoteForUser(username, content);
    }
    @GetMapping("/notes")
    @CrossOrigin()
    public List<Note> getNotes(@AuthenticationPrincipal UserDetails userDetails)
    {
        return noteService.getNotesForUser(userDetails.getUsername());
    }
    @PutMapping("/notes/{noteId}")
    public Note updateNote(@PathVariable Long noteId,
                           @RequestBody String content,
                           @AuthenticationPrincipal
    UserDetails userDetails)
    {
        return noteService.updateNoteForUser(noteId, content, userDetails.getUsername());
    }
    @DeleteMapping("/notes/{noteId}")
    public void deleteNoteForUser(@PathVariable Long noteId,
                                  @AuthenticationPrincipal UserDetails userDetails)
    {
        noteService.deleteNoteForUser(noteId, userDetails.getUsername());
    }

}
