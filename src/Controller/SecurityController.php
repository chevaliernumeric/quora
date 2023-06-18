<?php

namespace App\Controller;

use DateTime;
use App\Entity\User;
use App\Form\UserType;
use App\Service\Uploader;
use App\Entity\ResetPassword;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use App\Repository\ResetPasswordRepository;
use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Security\Http\Authenticator\FormLoginAuthenticator;
use Symfony\Component\Security\Http\Authentication\UserAuthenticatorInterface;

class SecurityController extends AbstractController
{
    public function __construct(private FormLoginAuthenticator $authenticate)
    {
    }
    #[Route('/signup', name: 'signup')]
    public function signup(Uploader $uploader,MailerInterface $mailer, UserAuthenticatorInterface $authenticator, Request $request, EntityManagerInterface $em, UserPasswordHasherInterface $passwordHasher): Response
    {
        $user = new User();
        $userForm = $this->createForm(UserType::class, $user);

        $userForm->handleRequest($request);
        if ($userForm->isSubmitted() && $userForm->isValid()) {
            $picture = $userForm->get('pictureFile')->getData();
            $user->setPicture($uploader->getProfileImage($picture));
           
            $hasher = $passwordHasher->hashPassword($user, $user->getPassword());
            $user->setPassword($hasher);
            $em->persist($user);
            $em->flush();
            $this->addFlash("success", "Bienvenu sur Wonder !");
            $email = new TemplatedEmail();
            $email->to($user->getEmail())
                ->subject("Bienvenu sur Wonder")
                ->htmlTemplate('@email_templates/welcome.html.twig')
                ->context([
                    'username' => $user->getFirstname()
                ]);
            $mailer->send($email);
            return $authenticator->authenticateUser(
                $user,
                $this->authenticate,
                $request
            );
        }
        return $this->render('security/signup.html.twig', [
            'form' => $userForm->createView(),
        ]);
    }
    #[Route('/login', name: 'login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        if ($this->getUser()) {
            return $this->redirectToRoute('home');
        }
        $error = $authenticationUtils->getLastAuthenticationError();
        $username = $authenticationUtils->getLastUsername();
        return $this->render('security/login.html.twig', [
            'error' => $error,
            'username' => $username
        ]);
    }
    #[Route('/logout', name: 'logout')]
    public function logout()
    {
    }
    #[Route('/reset_password/{token}', name: 'reset_password')]
    public function resetPassword(UserPasswordHasherInterface $passwordHasher,Request $request,EntityManagerInterface $em,string $token,ResetPasswordRepository $resetPasswordRepo)
    {
        $resetPassword = $resetPasswordRepo->findOneBy(['token'=>$token]);
        if(!$resetPassword || $resetPassword->getExpiredAt() < new \DateTime('now')){
            if($resetPassword){
                $em->remove($resetPassword);
                $em->flush();
            }
            $this->addFlash('error', 'Votre demande est expirée veuillez refaire une demande.');
            return $this->redirectToRoute('login');
        }
        $passwordForm = $this->createFormBuilder()->add('password',PasswordType::class,[
            'label'=>'Nouveau mot de passe',
            'constraints'=>[
                new Length([
                    'min' => 6,
                    'minMessage' => 'Le mot de passe doit faire au moins 6 caractères.'
                  ]),
                  new NotBlank([
                    'message' => 'Veuillez renseigner un mot de passe.'
                  ])
            ]
        ])->getForm();
        $passwordForm->handleRequest($request);
        if($passwordForm->isSubmitted() && $passwordForm->isValid()){
            $password = $passwordForm->get('password')->getData();
            $user = $resetPassword->getUser();
            $hash= $passwordHasher->hashPassword($user,$password);
            $user->setPassword($hash);
            $em->flush();
            $this->addFlash('success', 'Votre mot de passe a été modifié.');
            return $this->redirectToRoute('login');
        }
        return $this->render('security/reset_password_form.html.twig', [
            'form' => $passwordForm->createView()
          ]);
    }
    #[Route('/reset_password_request', name: 'reset_password_request')]

    public function resetPasswordRequest(MailerInterface $mailer,EntityManagerInterface $em,Request $request, UserRepository $userRep, ResetPasswordRepository $resetPasswordRepo)
    {
        $emailForm = $this->createFormBuilder()->add('email', EmailType::class, [
            'constraints' => [
                new NotBlank([
                    'message' => 'Veuillez renseigner votre email'
                ])
            ]
        ])->getForm();
        $emailForm->handleRequest($request);
        if ($emailForm->isSubmitted() && $emailForm->isValid()) {
            $emailValue = $emailForm->get("email")->getData();
            $user = $userRep->findOneBy(["email" => $emailValue]);
            if ($user) {
                $oldPassword = $resetPasswordRepo->findOneBy(["user" => $user]);
                if($oldPassword){
                    $em->remove($oldPassword);
                    $em->flush();

                }
                $resetPassword = new ResetPassword();
                $resetPassword->setUser($user);
                $resetPassword->setExpiredAt(new \DateTimeImmutable("+2 hours"));
                $token = substr(str_replace(['+', '/', '='], '', base64_encode(random_bytes(30))), 0, 20);
                $resetPassword->setToken($token);
                $em->persist($resetPassword);
                $em->flush();
                $email = new TemplatedEmail();
                $email->to($emailValue)
                        ->subject('Demande de réinitialisation de mot de passe')
                        ->htmlTemplate('@email_templates/reset_password_request.html.twig')
                        ->context([
                            'token'=>$token
                        ]);
                        $mailer->send($email);
            }
            $this->addFlash('success', 'Un email vous a été envoyé pour réinitialiser votre mot de passe');
            return $this->redirectToRoute('home');

        }
        return $this->render('security/reset_password_request.html.twig', [
            'form' => $emailForm->createView()
        ]);
    }
}
