package se.digg.wallet.r2ps.commons.dto.servicetype;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Registry for session tasks. A session task is a defined task that should be performed under a
 * specific session. Each task type has a defined max duration for sessions running under this task.
 * A server may also use knowledge of the defined task to limit what operations that are allowed
 * under this task as well as ending the session if the task is known to be complete.
 */
public class SessionTaskRegistry {

  /** Map holding registered session tasks */
  Map<String, SessionTask> sessionTasks;

  public SessionTaskRegistry() {
    // Create an empty registry
    this.sessionTasks = new HashMap<>();
  }

  /**
   * Retrieves the {@link SessionTask} associated with the specified unique identifier.
   *
   * @param id the unique identifier of the session task to retrieve
   * @return the {@link SessionTask} corresponding to the given identifier, or null if no task is
   *     found with the specified identifier
   */
  public SessionTask getSessionTaskById(String id) {
    return sessionTasks.get(id);
  }

  /**
   * Registers a new session task in the registry.
   *
   * @param sessionTask the {@link SessionTask} to be registered
   */
  public void registerSessionTask(SessionTask sessionTask) {
    this.sessionTasks.put(sessionTask.id(), sessionTask);
  }

  /**
   * Registers a new session task in the registry using the provided unique identifier and maximum
   * duration.
   *
   * @param id the unique identifier for the session task to be registered
   * @param maxDuration the maximum duration for which the session task is allowed to run
   */
  public void registerSessionTask(String id, Duration maxDuration) {
    SessionTask sessionTask = new SessionTask(id, maxDuration);
    this.registerSessionTask(sessionTask);
  }

  /**
   * Removes a session task from the registry.
   *
   * @param id the unique identifier of the session task to be removed
   */
  public void removeSessionTask(String id) {
    this.sessionTasks.remove(id);
  }

  /**
   * Removes all session tasks from the registry.
   *
   * <p>This method clears all entries in the internal map of session tasks, leaving the registry
   * empty.
   */
  public void removeAllSessionTasks() {
    this.sessionTasks.clear();
  }
}
