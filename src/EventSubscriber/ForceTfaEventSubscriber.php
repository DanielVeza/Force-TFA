<?php

namespace Drupal\force_tfa\EventSubscriber;

use Drupal\Component\Render\FormattableMarkup;
use Drupal\Core\Config\Config;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\Url;
use Drupal\user\UserData;
use Drupal\user\UserInterface;
use Drupal\Core\Config\ConfigFactory;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Cmf\Component\Routing\RouteObjectInterface;

class ForceTfaEventSubscriber implements EventSubscriberInterface {

  /**
   * The currently logged in user.
   *
   * @var \Drupal\Core\Session\AccountProxyInterface
   */
  protected $currentUser;

  /**
   * The messenger service.
   *
   * @var \Drupal\Core\Messenger\MessengerInterface
   */
  protected $messenger;

  /**
   * The user storage.
   *
   * @var \Drupal\Core\Entity\EntityStorageInterface
   */
  protected $userStorage;

  /**
   * The request object.
   *
   * @var \Symfony\Component\HttpFoundation\Request|null
   */
  protected $request;

  /**
   * @var UserData
   */
  protected $userData;

  /**
   * @var configFactory
   */
  protected $configFactory;

  /**
   * PasswordPolicyEventSubscriber constructor.
   *
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   The currently logged in user.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   The messenger service.
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The request stack.
   * @param UserData $userData
   *   The userData service.
   * @param ConfigFactory $configFactory
   *   The configuration object factory.
   *
   * @throws \Drupal\Component\Plugin\Exception\InvalidPluginDefinitionException
   * @throws \Drupal\Component\Plugin\Exception\PluginNotFoundException
   */
  public function __construct(AccountProxyInterface $currentUser, EntityTypeManagerInterface $entityTypeManager, MessengerInterface $messenger, RequestStack $requestStack, UserData $userData, ConfigFactory $configFactory) {
    $this->currentUser = $currentUser;
    $this->messenger = $messenger;
    $this->request = $requestStack->getCurrentRequest();
    $this->userData = $userData;
    $this->userStorage = $entityTypeManager->getStorage('user');
    $this->configFactory = $configFactory;
  }

  /**
   * Event callback to check if TFA needs to be forced.
   */
  public function checkForTfa(GetResponseEvent $event) {
    // No need to go further if TFA is disabled.
    $tfaSettings = $this->configFactory->get('tfa.settings');
    if (!$tfaSettings->get('enabled')) {
      return;
    }
    $route_name = $this->request->attributes->get(RouteObjectInterface::ROUTE_NAME);
    // Ignore route for jsonapi calls.
    if (strpos($route_name, 'jsonapi') !== FALSE) {
      return;
    }
    // TFA only matters if the user is logged in.
    if (!$this->currentUser->isAuthenticated()) {
      return;
    }
    // Some safe routes that shouldn't be redirected from.
    $ignore_routes = in_array($route_name, [
      'entity.user.edit_form',
      'system.ajax',
      'user.logout',
      'admin_toolbar_tools.flush',
      'tfa.overview',
      'tfa.validation.setup'
    ]);
    /* @var $user \Drupal\user\UserInterface */
    $user = $this->userStorage->load($this->currentUser->id());
    // Check if the user is required to use TFA.
    $userHasTFARole = $this->doesUserHaveTfaRole($user);
    // We don't want to mess with AJAX requests.
    $isAjax = $this->request->headers->get('X_REQUESTED_WITH') === 'XMLHttpRequest';
    $tfaSettings = $this->userData->get('tfa', $user->id());
    // tfa_user_settings only exists if the user has NOT yet set up TFA.
    $tfaSet = isset($tfaSettings['tfa_user_settings']) && !empty($tfaSettings['tfa_user_settings']['data']['plugins']);
    if ($user && $userHasTFARole && !$tfaSet && !$ignore_routes && !$isAjax) {
      // Redirect user.
      $url = new Url('tfa.overview', ['user' => $user->id()]);
      $url = $url
        ->setAbsolute()
        ->toString();
      $tfaValidationUrl = new Url('tfa.validation.setup', [
          'user' => $user->id(),
          'method' => 'ga_login_totp'
        ]
      );
      $tfaValidationUrl = $tfaValidationUrl
        ->setAbsolute()
        ->toString();
      // Removing existing errors to avoid duplicates.
      // TODO - Is this the best thing to do?
      $this->messenger->deleteByType('error');
      $message = new FormattableMarkup('You are required to setup two-factor authentication <a href="@link">here.</a>', ['@link' => $tfaValidationUrl]);
      $this->messenger->addError($message);
      $event->setResponse(new RedirectResponse($url));
    }
  }

  /**
   * Checks if a user should use TFA.
   *
   * @param UserInterface $user
   * @return bool
   */
  private function doesUserHaveTfaRole(UserInterface $user) {
    $tfaSettings = \Drupal::configFactory()->get('tfa.settings');
    $required_roles = array_keys(array_filter($tfaSettings->get('required_roles')));
    $userRoles = $user->getRoles();
    return sizeof(array_intersect($required_roles, $userRoles)) > 0;
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    $events[KernelEvents::REQUEST][] = ['checkForTfa'];
    return $events;
  }
}
