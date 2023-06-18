<?php

namespace App\Repository;

use App\Entity\Question;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<Question>
 *
 * @method Question|null find($id, $lockMode = null, $lockVersion = null)
 * @method Question|null findOneBy(array $criteria, array $orderBy = null)
 * @method Question[]    findAll()
 * @method Question[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class QuestionRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Question::class);
    }

    public function getLastQuestionsWithAuthors(){
        return $this->createQueryBuilder('q')
                    ->leftJoin('q.author','a')
                    ->addSelect('a')
                    ->orderBy('q.createdAt','DESC')
                    ->getQuery()
                    ->getResult();
    }
    public function getQuestionsWithCommentsAndAuthors(string $id){
        return $this->createQueryBuilder('q')
                    ->andWhere('q.id = :id' )
                    ->setParameter('id',$id)
                    ->leftJoin('q.author','a')
                    ->addSelect('a')
                    ->leftJoin('q.comments','c')
                    ->addSelect('c')
                    ->leftJoin('c.author','ca')
                    ->addSelect('ca')
                    ->getQuery()
                    ->getOneOrNullResult();
    }

    public function findBySearch(string $query){
        return $this->createQueryBuilder('q')
            ->select('q.title,q.id')
            ->where('q.title LIKE :search')
            ->setParameter('search',"%{$query}%")
            ->getQuery()
            ->getResult();
    }

    public function add(Question $entity, bool $flush = false): void
    {
        $this->getEntityManager()->persist($entity);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    public function remove(Question $entity, bool $flush = false): void
    {
        $this->getEntityManager()->remove($entity);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

//    /**
//     * @return Question[] Returns an array of Question objects
//     */
//    public function findByExampleField($value): array
//    {
//        return $this->createQueryBuilder('q')
//            ->andWhere('q.exampleField = :val')
//            ->setParameter('val', $value)
//            ->orderBy('q.id', 'ASC')
//            ->setMaxResults(10)
//            ->getQuery()
//            ->getResult()
//        ;
//    }

//    public function findOneBySomeField($value): ?Question
//    {
//        return $this->createQueryBuilder('q')
//            ->andWhere('q.exampleField = :val')
//            ->setParameter('val', $value)
//            ->getQuery()
//            ->getOneOrNullResult()
//        ;
//    }
}
